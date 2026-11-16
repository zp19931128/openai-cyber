//! 有界保存被拦截请求的脱敏上下文，持久化交由宿主状态服务

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
    call::host::{self, StateGetRequest, StateGetResult, StatePutRequest, StatePutResult},
    client::{HostClient, MiddlewareRequest, SessionError},
};
use regex::Regex;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::sync::Mutex;

pub(crate) const MAX_EVENTS: usize = 100;
pub(crate) const MAX_CONTEXT_CHARS: usize = 4000;
pub(crate) const MAX_BYTES: usize = 192 * 1024;
pub(crate) const RETENTION_DAYS: u64 = 7;
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_RAW_CONTEXT_SCAN_BYTES: usize = 16 * 1024;
const RETENTION_MS: u64 = RETENTION_DAYS * 24 * 60 * 60 * 1000;
const STATE_NAMESPACE: &str = "audit";
const STATE_KEY: &str = "recent";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEvent {
    pub id: String,
    pub timestamp_ms: u64,
    pub request_id: String,
    pub client_key_id: Option<String>,
    pub model: Option<String>,
    pub transport: String,
    pub rule_id: Option<String>,
    pub category: Option<String>,
    pub policy_version: Option<String>,
    pub reason: String,
    pub context: Option<String>,
    pub context_truncated: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    events: Vec<AuditEvent>,
}

#[derive(Serialize)]
pub(crate) struct AuditSnapshot {
    events: Vec<AuditEvent>,
    retention: Retention,
    recording: Recording,
}

#[derive(Serialize)]
struct Retention {
    max_events: usize,
    max_context_chars: usize,
    max_bytes: usize,
    retention_days: u64,
    capture_context: bool,
}

#[derive(Serialize)]
struct Recording {
    failures_since_start: u64,
    last_error_at_ms: Option<u64>,
}

pub(crate) struct AuditStore {
    capture_context: bool,
    lock: Mutex<()>,
    sequence: AtomicU64,
    failures: AtomicU64,
    last_error_at_ms: AtomicU64,
}

impl AuditStore {
    pub(crate) fn new(capture_context: bool) -> Self {
        Self {
            capture_context,
            lock: Mutex::new(()),
            sequence: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            last_error_at_ms: AtomicU64::new(0),
        }
    }

    pub(crate) async fn append(
        &self,
        host: &HostClient,
        request: &MiddlewareRequest,
        details: &Value,
        reason: &str,
    ) -> bool {
        let timestamp_ms = now_ms();
        let context = capture(&request.body, self.capture_context);
        let event = AuditEvent {
            id: format!(
                "{}-{}-{}",
                std::process::id(),
                timestamp_ms,
                self.sequence.fetch_add(1, Ordering::Relaxed)
            ),
            timestamp_ms,
            request_id: safe_metadata(&request.head.request_id, 128),
            client_key_id: (!request.head.client_key_id.is_empty())
                .then(|| safe_metadata(&request.head.client_key_id, 128)),
            model: request.head.model.as_deref().map(|v| safe_metadata(v, 256)),
            transport: serde_json::to_value(request.head.transport)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into()),
            rule_id: field(details, "rule_id"),
            category: field(details, "category"),
            policy_version: field(details, "policy_version"),
            reason: match details.get("code").and_then(Value::as_str) {
                Some("keyword_policy_blocked") => "命中关键词拦截规则".into(),
                Some("keyword_inspection_failed") => inspection_failure_reason(details),
                _ => safe_metadata(reason, 256),
            },
            context: context.text,
            context_truncated: context.truncated,
        };
        let _guard = self.lock.lock().await;
        self.append_locked(host, event).await.is_ok()
    }

    async fn append_locked(&self, host: &HostClient, event: AuditEvent) -> Result<(), PluginFault> {
        for _ in 0..3 {
            let (mut record, version) = load(host).await?;
            prune(&mut record, now_ms());
            record.events.insert(0, event.clone());
            record
                .events
                .sort_by_key(|event| std::cmp::Reverse(event.timestamp_ms));
            bound(&mut record)?;
            match save(host, &record, version).await {
                Ok(()) => return Ok(()),
                Err(error) if error.code == ErrorCode::Conflict => continue,
                Err(error) => return Err(error),
            }
        }
        Err(state_error())
    }

    pub(crate) async fn snapshot(&self, host: &HostClient) -> Result<AuditSnapshot, PluginFault> {
        let _guard = self.lock.lock().await;
        let mut result = None;
        for _ in 0..3 {
            let (mut record, version) = load(host).await?;
            let changed = prune(&mut record, now_ms());
            if changed {
                match save(host, &record, version).await {
                    Ok(()) => {}
                    Err(error) if error.code == ErrorCode::Conflict => continue,
                    Err(error) => return Err(error),
                }
            }
            result = Some(record);
            break;
        }
        let record = result.ok_or_else(state_error)?;
        let last_error = self.last_error_at_ms.load(Ordering::Relaxed);
        Ok(AuditSnapshot {
            events: record.events,
            retention: Retention {
                max_events: MAX_EVENTS,
                max_context_chars: MAX_CONTEXT_CHARS,
                max_bytes: MAX_BYTES,
                retention_days: RETENTION_DAYS,
                capture_context: self.capture_context,
            },
            recording: Recording {
                failures_since_start: self.failures.load(Ordering::Relaxed),
                last_error_at_ms: (last_error != 0).then_some(last_error),
            },
        })
    }

    pub(crate) fn record_failure(&self) {
        let _ = self
            .failures
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
        self.last_error_at_ms.store(now_ms(), Ordering::Relaxed);
    }
}

async fn load(host: &HostClient) -> Result<(AuditRecord, Option<u64>), PluginFault> {
    let result: StateGetResult = callback(
        host,
        host::STATE_GET,
        &StateGetRequest {
            namespace: STATE_NAMESPACE.into(),
            key: STATE_KEY.into(),
        },
    )
    .await?;
    let Some(record) = result.record else {
        return Ok((AuditRecord::default(), None));
    };
    if record.schema_version != 1 {
        return Err(state_error());
    }
    let decoded = decode_record(record.value)?;
    Ok((decoded, Some(record.version)))
}

fn decode_record(value: Value) -> Result<AuditRecord, PluginFault> {
    if serde_json::to_vec(&value).map_err(|_| state_error())?.len() > MAX_BYTES {
        return Err(state_error());
    }
    let decoded: AuditRecord = serde_json::from_value(value).map_err(|_| state_error())?;
    if decoded.events.len() > MAX_EVENTS
        || decoded.events.iter().any(|event| {
            event
                .context
                .as_ref()
                .is_some_and(|v| v.chars().count() > MAX_CONTEXT_CHARS)
        })
    {
        return Err(state_error());
    }
    Ok(decoded)
}

async fn save(
    host: &HostClient,
    record: &AuditRecord,
    version: Option<u64>,
) -> Result<(), PluginFault> {
    let _: StatePutResult = callback(
        host,
        host::STATE_PUT,
        &StatePutRequest {
            namespace: STATE_NAMESPACE.into(),
            key: STATE_KEY.into(),
            value: serde_json::to_value(record).map_err(|_| state_error())?,
            expected_version: version,
        },
    )
    .await?;
    Ok(())
}

async fn callback<I: Serialize, O: DeserializeOwned>(
    host: &HostClient,
    method: &str,
    input: &I,
) -> Result<O, PluginFault> {
    let reply = host
        .call(
            method,
            serde_json::to_value(input).map_err(|_| state_error())?,
            Vec::new(),
        )
        .await
        .map_err(SessionError::into_plugin_fault)?;
    if !reply.payload.is_empty() {
        return Err(state_error());
    }
    serde_json::from_value(reply.result).map_err(|_| state_error())
}

fn prune(record: &mut AuditRecord, timestamp_ms: u64) -> bool {
    let previous = record.events.len();
    let earliest = timestamp_ms.saturating_sub(RETENTION_MS);
    record.events.retain(|event| event.timestamp_ms >= earliest);
    record.events.len() != previous
}

fn bound(record: &mut AuditRecord) -> Result<(), PluginFault> {
    record.events.truncate(MAX_EVENTS);
    while serde_json::to_vec(record).map_err(|_| state_error())?.len() > MAX_BYTES {
        if record.events.pop().is_none() {
            return Err(state_error());
        }
    }
    Ok(())
}

fn state_error() -> PluginFault {
    PluginFault::new(ErrorCode::Fault, "拦截日志状态不可用")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| u64::try_from(v.as_millis()).unwrap_or(u64::MAX))
}

fn field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(|v| safe_metadata(v, 128))
}

fn safe_metadata(text: &str, max: usize) -> String {
    redact(text).chars().take(max).collect()
}

fn inspection_failure_reason(details: &Value) -> String {
    let failure = details
        .get("inspection_error")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let category = match failure {
        "Request exceeds the 2 MiB keyword inspection limit." => "请求体超过 2 MiB 检查限制",
        "Request must be valid JSON within the supported nesting limit." => {
            "JSON 格式无效或超过嵌套限制"
        }
        "Request must be a JSON object." => "JSON 顶层必须是对象",
        "Combined message text exceeds the keyword inspection limit." => {
            "待检查文本超过 2 MiB 限制"
        }
        _ => "请求无法完成关键词检查",
    };
    let bytes = details.get("request_bytes").and_then(Value::as_u64);
    match bytes {
        Some(bytes) => format!("{category}（请求体 {bytes} 字节）"),
        None => category.to_owned(),
    }
}

struct CapturedContext {
    text: Option<String>,
    truncated: bool,
}

fn capture(body: &[u8], enabled: bool) -> CapturedContext {
    if !enabled {
        return empty_context();
    }

    if body.len() <= MAX_REQUEST_BYTES
        && let Ok(value) = serde_json::from_slice::<Value>(body)
    {
        let mut collector = ContextCollector {
            text: String::new(),
            truncated: false,
        };
        if let Some(object) = value.as_object() {
            for key in ["instructions", "prompt", "input", "messages"] {
                if let Some(value) = object.get(key) {
                    collector.collect(value, key, 0);
                }
            }
        }
        if !collector.text.is_empty() {
            return CapturedContext {
                text: Some(collector.text),
                truncated: collector.truncated,
            };
        }
    }

    capture_raw_excerpt(body)
}

fn empty_context() -> CapturedContext {
    CapturedContext {
        text: None,
        truncated: false,
    }
}

fn capture_raw_excerpt(body: &[u8]) -> CapturedContext {
    if body.is_empty() {
        return empty_context();
    }
    let scan_len = body.len().min(MAX_RAW_CONTEXT_SCAN_BYTES);
    let raw = String::from_utf8_lossy(&body[..scan_len]);
    let safe = redact(&raw);
    let prefix = "[请求正文片段，未解析]\n";
    let available = MAX_CONTEXT_CHARS.saturating_sub(prefix.chars().count());
    let truncated = body.len() > scan_len || safe.chars().count() > available;
    let excerpt_limit = available.saturating_sub(usize::from(truncated));
    let mut text: String = safe.chars().take(excerpt_limit).collect();
    if truncated {
        text.push('…');
    }
    let mut context = String::with_capacity(prefix.len() + text.len());
    context.push_str(prefix);
    context.push_str(&text);
    CapturedContext {
        text: Some(context),
        truncated,
    }
}

struct ContextCollector {
    text: String,
    truncated: bool,
}

impl ContextCollector {
    fn collect(&mut self, value: &Value, path: &str, depth: usize) {
        if depth > 32 {
            self.truncated = true;
            return;
        }
        match value {
            Value::String(text) => self.add(path, text),
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    if self.truncated {
                        break;
                    }
                    self.collect(value, &format!("{path}[{index}]"), depth + 1);
                }
            }
            Value::Object(values) => {
                let role = values.get("role").and_then(Value::as_str).filter(|v| {
                    matches!(*v, "system" | "developer" | "user" | "assistant" | "tool")
                });
                let path = role.map_or_else(|| path.to_owned(), |v| format!("{path} ({v})"));
                for (key, value) in values {
                    if sensitive_key(key) {
                        continue;
                    }
                    if matches!(
                        key.as_str(),
                        "text"
                            | "content"
                            | "input"
                            | "instructions"
                            | "prompt"
                            | "arguments"
                            | "output"
                            | "function"
                    ) {
                        self.collect(value, &format!("{path}.{key}"), depth + 1);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn add(&mut self, path: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let safe = redact(text);
        let mut addition = format!("[{path}]\n{safe}\n\n");
        let available = MAX_CONTEXT_CHARS.saturating_sub(self.text.chars().count());
        if addition.chars().count() > available {
            addition = addition.chars().take(available).collect();
            self.truncated = true;
        }
        self.text.push_str(&addition);
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "passphrase"
            | "secret"
            | "token"
            | "apikey"
            | "authorization"
            | "cookie"
            | "privatekey"
            | "clientsecret"
            | "accesskey"
            | "accesstoken"
            | "refreshtoken"
    )
}

fn redact(text: &str) -> String {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| [
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        r"\bsk-[A-Za-z0-9_-]{8,}",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16})",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        r#"(?i)(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|passwd|passphrase|client[_ -]?secret|private[_ -]?key|authorization|cookie|secret|token)[\"']?\s*[:=]\s*(?:\"(?:\\.|[^\"\\])*(?:\"|\\?\z)|'(?:\\.|[^'\\])*(?:'|\\?\z)|[^\s,;}]+)"#,
    ].into_iter().map(|pattern| Regex::new(pattern).expect("Static redaction expression must compile")).collect());
    let mut result = text.to_owned();
    for pattern in patterns.iter() {
        result = pattern.replace_all(&result, "[已脱敏]").into_owned();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn context_preserves_message_roles_without_credentials_or_headers() {
        let input = json!({
            "messages": [
                {"role":"user", "content":"use sk-123456789abcdef and Bearer abc.def.ghi password=hunter2"},
                {"role":"assistant", "content":[{"type":"text","text":"ordinary answer"}, {"password":"secret-value"}]},
                {"role":"user", "content":"-----BEGIN PRIVATE KEY-----\nsecret pem\n-----END PRIVATE KEY-----"}
            ],
            "authorization":"header secret",
            "metadata":{"token":"metadata-secret"}
        });
        let context = capture(&serde_json::to_vec(&input).unwrap(), true)
            .text
            .unwrap();
        assert!(context.contains("messages[0] (user).content"));
        assert!(context.contains("ordinary answer"));
        for secret in [
            "sk-123456789abcdef",
            "abc.def.ghi",
            "hunter2",
            "secret-value",
            "secret pem",
            "header secret",
            "metadata-secret",
        ] {
            assert!(!context.contains(secret));
        }
        assert!(context.contains("[已脱敏]"));
    }

    #[test]
    fn escaped_json_credentials_and_other_common_tokens_are_redacted() {
        let text = r#"{"password":"safe\"remaining secret", "api_key":"unusual-key"} ghp_0123456789abcdefghijkl xoxb-123456789012345 AKIA0123456789ABCDEF"#;
        let safe = redact(text);
        for secret in [
            "remaining secret",
            "unusual-key",
            "0123456789abcdefghijkl",
            "xoxb-123456789012345",
            "AKIA0123456789ABCDEF",
        ] {
            assert!(!safe.contains(secret));
        }
    }

    #[test]
    fn disabling_context_still_avoids_recording_input() {
        let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
        for body in [
            br#"{"input":"secret"}"#.as_slice(),
            b"invalid password=secret".as_slice(),
            oversized.as_slice(),
        ] {
            let context = capture(body, false);
            assert!(context.text.is_none());
            assert!(!context.truncated);
        }
    }

    #[test]
    fn malformed_json_saves_only_a_redacted_bounded_excerpt() {
        let context = capture(
            br#"{"messages":[{"role":"user","content":"help me"}],"api_key":"unfinished-secret""#,
            true,
        );
        let text = context.text.unwrap();
        assert!(text.starts_with("[请求正文片段，未解析]"));
        assert!(text.contains("help me"));
        assert!(!text.contains("unfinished-secret"));
        assert!(text.contains("[已脱敏]"));
    }

    #[test]
    fn valid_json_without_known_message_fields_falls_back_to_sanitized_excerpt() {
        let context = capture(br#"{"body":"request text","token":"long-secret"}"#, true);
        let text = context.text.unwrap();
        assert!(text.contains("request text"));
        assert!(!text.contains("long-secret"));
    }

    #[test]
    fn unclosed_quoted_credentials_with_spaces_are_redacted_through_end() {
        for body in [
            br#"{"api_key":"first second third"#.as_slice(),
            br#"{"password":"first second\"third fourth\"#.as_slice(),
            b"not json token='first second third".as_slice(),
        ] {
            let text = capture(body, true).text.unwrap();
            for secret in ["first", "second", "third", "fourth"] {
                assert!(!text.contains(secret));
            }
            assert!(text.contains("[已脱敏]"));
        }
    }

    #[test]
    fn credentials_cut_by_raw_scan_limit_are_redacted_through_end() {
        let mut body = br#"{"password":"first second "#.to_vec();
        body.resize(MAX_REQUEST_BYTES + 1, b'x');
        let context = capture(&body, true);
        let text = context.text.unwrap();
        assert!(context.truncated);
        assert!(!text.contains("first"));
        assert!(!text.contains("second"));
        assert!(text.contains("[已脱敏]"));
        assert!(text.chars().count() <= MAX_CONTEXT_CHARS);
    }

    #[test]
    fn raw_scan_limit_may_split_utf8_without_panicking_or_exceeding_limit() {
        let mut body = vec![b'x'; MAX_RAW_CONTEXT_SCAN_BYTES - 1];
        body.extend_from_slice("🦀".as_bytes());
        body.resize(MAX_REQUEST_BYTES + 1, b'y');
        let context = capture(&body, true);
        let text = context.text.unwrap();
        assert!(context.truncated);
        assert_eq!(text.chars().count(), MAX_CONTEXT_CHARS);
        assert!(text.ends_with('…'));
        assert!(!text.contains('y'));
    }

    #[test]
    fn oversized_body_captures_only_a_limited_prefix_and_marks_truncation() {
        let mut body = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let credential = b"Bearer abcdefghijklmnop ";
        body[..credential.len()].copy_from_slice(credential);
        let context = capture(&body, true);
        let text = context.text.unwrap();
        assert!(context.truncated);
        assert!(!text.contains("abcdefghijklmnop"));
        assert_eq!(text.chars().count(), MAX_CONTEXT_CHARS);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn inspection_failure_reason_records_safe_class_and_body_size() {
        let reason = inspection_failure_reason(&json!({
            "inspection_error": "Request must be valid JSON within the supported nesting limit.",
            "request_bytes": 1234
        }));
        assert_eq!(reason, "JSON 格式无效或超过嵌套限制（请求体 1234 字节）");
    }

    #[test]
    fn unicode_context_has_one_shared_limit_and_explicit_truncation() {
        let input = json!({"messages":[{"role":"user","content":"中🦀".repeat(3000)}, {"role":"assistant","content":"later"}]});
        let context = capture(&serde_json::to_vec(&input).unwrap(), true);
        assert!(context.truncated);
        let text = context.text.unwrap();
        assert_eq!(text.chars().count(), MAX_CONTEXT_CHARS);
        assert!(!text.contains("later"));
    }

    fn event(id: usize, timestamp_ms: u64) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp_ms,
            request_id: format!("request-{id}"),
            client_key_id: None,
            model: None,
            transport: "http_sse".into(),
            rule_id: None,
            category: None,
            policy_version: None,
            reason: "命中关键词规则".into(),
            context: Some("中".repeat(MAX_CONTEXT_CHARS)),
            context_truncated: false,
        }
    }

    #[test]
    fn retention_prunes_expired_records_and_evicts_oldest_under_byte_budget() {
        let timestamp_ms = RETENTION_MS * 2;
        let mut record = AuditRecord {
            events: (0..120)
                .map(|id| event(id, timestamp_ms - id as u64))
                .collect(),
        };
        record.events.push(event(121, 0));
        assert!(prune(&mut record, timestamp_ms));
        bound(&mut record).unwrap();
        assert!(record.events.len() < MAX_EVENTS);
        assert!(serde_json::to_vec(&record).unwrap().len() <= MAX_BYTES);
        assert_eq!(record.events[0].id, "0");
        assert!(!record.events.iter().any(|event| event.id == "121"));
    }

    #[test]
    fn malformed_state_is_rejected_instead_of_silently_overwritten() {
        assert!(decode_record(json!({"events":"not an array"})).is_err());
        assert!(decode_record(json!({"events":[],"unexpected":true})).is_err());
        let mut event = event(1, 0);
        event.context = Some("a".repeat(MAX_CONTEXT_CHARS + 1));
        assert!(decode_record(json!({"events":[event]})).is_err());
    }
}
