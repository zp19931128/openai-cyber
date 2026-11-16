//! 在管理员页面查看校验测试并以版本检查保存当前实例规则

use std::{collections::HashSet, time::Duration};

use cpr_keyword_guard::engine::{GuardConfig, Rule, RuleSet};
use gateway_plugin_sdk::{
    Handshake,
    call::middleware::{MiddlewareHeader, http::Version},
    client::{HostClient, HttpBody, HttpFrame, HttpRequest},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAXIMUM_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_HOST_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const RULE_FIELDS: [&str; 5] = [
    "schema_version",
    "disabled_builtin_ids",
    "extra_keywords",
    "extra_regexes",
    "custom_rules",
];

pub(crate) struct RulesService {
    instance_id: String,
    artifact_sha256: String,
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: u16,
    pub body: Value,
}

impl ApiError {
    pub(crate) fn new(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            body: json!({"error":{"code":code,"message":message}}),
        }
    }

    fn invalid_configuration(details: String) -> Self {
        Self {
            status: 422,
            body: json!({"error":{"code":"invalid_configuration","message":"规则配置无效","details":details}}),
        }
    }

    fn unavailable() -> Self {
        Self::new(503, "rules_unavailable", "规则配置读取失败，请稍后重试")
    }

    fn conflict() -> Self {
        Self::new(409, "conflict", "插件配置已变化，请刷新页面后重新确认")
    }

    fn unknown_save() -> Self {
        Self::new(
            503,
            "save_outcome_unknown",
            "保存结果未确认，请刷新页面核对后再重试",
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationRequest {
    configuration: GuardConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestRequest {
    configuration: GuardConfig,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveRequest {
    expected_revision: u64,
    configuration: GuardConfig,
}

#[derive(Deserialize)]
struct Builtins {
    policy_version: String,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct BuiltinRule {
    #[serde(flatten)]
    rule: Rule,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Instance {
    id: String,
    name: String,
    artifact_sha256: String,
    enabled: bool,
    configuration: Value,
    bindings: Value,
    revision: u64,
}

impl RulesService {
    pub(crate) fn new(handshake: &Handshake) -> Self {
        Self {
            instance_id: handshake.instance_id.clone(),
            artifact_sha256: handshake.artifact_sha256.clone(),
        }
    }

    pub(crate) fn matches_instance(&self, instance_id: &str) -> bool {
        self.instance_id == instance_id
    }

    pub(crate) async fn handle(
        &self,
        host: &HostClient,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Value, ApiError> {
        match (method, path) {
            ("GET", "api/rules") if body.is_empty() => {
                let current = self.current_instance(host).await?;
                catalog(
                    extract_configuration(&current.configuration)?,
                    current.revision,
                )
            }
            ("POST", "api/rules/validate") => {
                let request: ConfigurationRequest = decode(body)?;
                let rules = compile(&request.configuration)?;
                Ok(
                    json!({"valid":true,"rule_count":rules.rule_count(),"policy_version":builtins()?.policy_version}),
                )
            }
            ("POST", "api/rules/test") => {
                let request: TestRequest = decode(body)?;
                let rules = compile(&request.configuration)?;
                let matched = rules.check(&request.text).map_err(|_| {
                    ApiError::new(400, "invalid_request", "测试文本超过检查大小限制")
                })?;
                Ok(
                    json!({"blocked":matched.is_some(),"matched":matched,"rule_count":rules.rule_count(),"policy_version":builtins()?.policy_version}),
                )
            }
            ("POST", "api/rules/save") => {
                let request: SaveRequest = decode(body)?;
                compile(&request.configuration)?;
                let current = self.current_instance(host).await?;
                if current.revision != request.expected_revision {
                    return Err(ApiError::conflict());
                }
                let update = update_request(&current, &request.configuration)?;
                let (status, response) = host_json(
                    host,
                    "POST",
                    "/api/admin/plugins/instances/update",
                    Some(update),
                )
                .await
                .map_err(|_| ApiError::unknown_save())?;
                if status == 409 {
                    return Err(ApiError::conflict());
                }
                if status == 400 {
                    return Err(ApiError::new(
                        422,
                        "invalid_configuration",
                        "CPR 拒绝此规则配置，当前配置可能尚未保存，请刷新核对",
                    ));
                }
                if status != 200 || response.get("code").and_then(Value::as_u64) != Some(200) {
                    return Err(ApiError::unknown_save());
                }
                let saved = response.get("data").ok_or_else(ApiError::unknown_save)?;
                if saved.get("id").and_then(Value::as_str) != Some(self.instance_id.as_str()) {
                    return Err(ApiError::unknown_save());
                }
                let revision = saved
                    .get("configRevision")
                    .and_then(Value::as_u64)
                    .filter(|revision| *revision > current.revision)
                    .ok_or_else(ApiError::unknown_save)?;
                catalog(request.configuration, revision)
            }
            _ => Err(ApiError::new(404, "not_found", "未找到插件管理接口")),
        }
    }

    async fn current_instance(&self, host: &HostClient) -> Result<Instance, ApiError> {
        let (status, response) = host_json(host, "GET", "/api/admin/plugins/instances", None)
            .await
            .map_err(|_| ApiError::unavailable())?;
        if status != 200 || response.get("code").and_then(Value::as_u64) != Some(200) {
            return Err(ApiError::unavailable());
        }
        let instances = response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(ApiError::unavailable)?;
        let mut own = instances
            .iter()
            .filter(|value| value.get("id").and_then(Value::as_str) == Some(&self.instance_id));
        let instance: Instance =
            serde_json::from_value(own.next().cloned().ok_or_else(ApiError::conflict)?)
                .map_err(|_| ApiError::unavailable())?;
        if own.next().is_some() || instance.artifact_sha256 != self.artifact_sha256 {
            return Err(ApiError::conflict());
        }
        Ok(instance)
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(ApiError::new(
            400,
            "invalid_request",
            "管理请求正文为空或超过大小限制",
        ));
    }
    serde_json::from_slice(body)
        .map_err(|_| ApiError::new(400, "invalid_request", "管理请求格式无效，请检查规则字段"))
}

fn compile(configuration: &GuardConfig) -> Result<RuleSet, ApiError> {
    RuleSet::load(configuration.clone()).map_err(ApiError::invalid_configuration)
}

fn builtins() -> Result<Builtins, ApiError> {
    serde_json::from_str(include_str!("../../rules/builtin.json"))
        .map_err(|_| ApiError::unavailable())
}

fn extract_configuration(value: &Value) -> Result<GuardConfig, ApiError> {
    let object = value.as_object().ok_or_else(ApiError::unavailable)?;
    let rules = RULE_FIELDS
        .into_iter()
        .filter_map(|key| {
            object
                .get(key)
                .cloned()
                .map(|value| (key.to_owned(), value))
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::from_value(Value::Object(rules)).map_err(|_| ApiError::unavailable())
}

fn catalog(configuration: GuardConfig, revision: u64) -> Result<Value, ApiError> {
    let compiled = compile(&configuration)?;
    let builtins = builtins()?;
    let disabled: HashSet<&str> = configuration
        .disabled_builtin_ids
        .iter()
        .map(String::as_str)
        .collect();
    let builtin_count = builtins.rules.len();
    let builtin_rules: Vec<BuiltinRule> = builtins
        .rules
        .into_iter()
        .map(|rule| BuiltinRule {
            enabled: !disabled.contains(rule.id.as_str()),
            rule,
        })
        .collect();
    Ok(json!({
        "policy_version":builtins.policy_version,
        "revision":revision,
        "counts":{
            "builtin":builtin_count,
            "builtin_enabled":builtin_count - disabled.len(),
            "keywords":configuration.extra_keywords.len(),
            "regexes":configuration.extra_regexes.len(),
            "custom":configuration.custom_rules.len(),
            "enabled":compiled.rule_count()
        },
        "configuration":configuration,
        "builtin_rules":builtin_rules
    }))
}

fn update_request(current: &Instance, configuration: &GuardConfig) -> Result<Value, ApiError> {
    let mut merged = current.configuration.clone();
    let object = merged.as_object_mut().ok_or_else(ApiError::unavailable)?;
    let new_rules = serde_json::to_value(configuration).map_err(|_| ApiError::unavailable())?;
    for key in RULE_FIELDS {
        object.insert(key.into(), new_rules[key].clone());
    }
    Ok(json!({
        "id":current.id,
        "instance":{
            "name":current.name,
            "artifactSha256":current.artifact_sha256,
            "enabled":current.enabled,
            "configuration":merged,
            "bindings":current.bindings,
            "expectedRevision":current.revision
        }
    }))
}

async fn host_json(
    host: &HostClient,
    method: &str,
    uri: &str,
    value: Option<Value>,
) -> Result<(u16, Value), ()> {
    let body = value
        .map(|value| serde_json::to_vec(&value))
        .transpose()
        .map_err(|_| ())?;
    let headers = if body.is_some() {
        vec![MiddlewareHeader {
            name: "content-type".into(),
            value: b"application/json".to_vec(),
        }]
    } else {
        Vec::new()
    };
    let request = HttpRequest {
        settings: Value::Null,
        method: method.into(),
        uri: uri.into(),
        version: Version::Http11,
        headers,
        timeout_ms: Some(45_000),
        body: body.map_or_else(HttpBody::empty, HttpBody::from_bytes),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut response = tokio::time::timeout_at(deadline, host.dispatch_http(request))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let result = tokio::time::timeout_at(deadline, async {
        let mut bytes = Vec::new();
        loop {
            match response.body.read().await {
                Ok(Some(HttpFrame::Data(chunk)))
                    if chunk.len() <= MAXIMUM_HOST_RESPONSE_BYTES.saturating_sub(bytes.len()) =>
                {
                    bytes.extend(chunk);
                }
                Ok(Some(HttpFrame::Trailers(_))) => {}
                Ok(None) => break,
                _ => {
                    return Err(());
                }
            }
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        Ok((response.status, value))
    })
    .await
    .map_err(|_| ())
    .and_then(std::convert::identity);
    if result.is_err() {
        let _ = tokio::time::timeout(Duration::from_millis(500), response.body.close()).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_describes_disabled_and_custom_rules_using_the_same_compiler() {
        let mut configuration = GuardConfig::default();
        let disabled = builtins().unwrap().rules[0].id.clone();
        configuration.disabled_builtin_ids.push(disabled.clone());
        configuration.extra_keywords.push("测试拒绝短语".into());
        let catalog = catalog(configuration, 19).unwrap();
        assert_eq!(catalog["revision"], 19);
        assert_eq!(catalog["counts"]["keywords"], 1);
        assert!(
            catalog["builtin_rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| rule["id"] == disabled && rule["enabled"] == false)
        );
        assert_eq!(catalog["counts"]["enabled"], catalog["counts"]["builtin"]);
    }

    #[test]
    fn save_replaces_rules_and_preserves_instance_audit_unknown_fields_and_secrets() {
        let current = Instance {
            id: "own-instance".into(),
            name: "current name".into(),
            artifact_sha256: "digest".into(),
            enabled: true,
            configuration: json!({"audit":{"capture_context":false},"future_option":{"keep":true},"extra_keywords":["old"]}),
            bindings: json!([{"stage":"request","enabled":true,"unknown":"preserve"}]),
            revision: 42,
        };
        let configuration = GuardConfig {
            extra_keywords: vec!["new".into()],
            ..GuardConfig::default()
        };
        let request = update_request(&current, &configuration).unwrap();
        assert_eq!(request["id"], "own-instance");
        let instance = &request["instance"];
        assert_eq!(instance["expectedRevision"], 42);
        assert_eq!(instance["name"], current.name);
        assert_eq!(instance["enabled"], true);
        assert_eq!(instance["bindings"], current.bindings);
        assert_eq!(instance["configuration"]["audit"]["capture_context"], false);
        assert_eq!(instance["configuration"]["future_option"]["keep"], true);
        assert_eq!(instance["configuration"]["extra_keywords"], json!(["new"]));
        assert!(instance.get("secrets").is_none());
        let rules = extract_configuration(&instance["configuration"]).unwrap();
        assert_eq!(rules.extra_keywords, ["new"]);
    }

    #[test]
    fn invalid_rules_and_unknown_management_fields_are_rejected() {
        let invalid = GuardConfig {
            extra_regexes: vec![".*".into()],
            ..GuardConfig::default()
        };
        assert_eq!(compile(&invalid).err().unwrap().status, 422);
        assert!(
            decode::<SaveRequest>(br#"{"expected_revision":1,"configuration":{},"id":"other"}"#)
                .is_err()
        );
        assert!(decode::<SaveRequest>(br#"{"configuration":{}}"#).is_err());
        assert!(decode::<TestRequest>(br#"{"configuration":{"audit":{}},"text":"x"}"#).is_err());
    }
}
