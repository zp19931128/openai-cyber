//! 检查本轮 JSON 请求中的字符串，不修改正文或推断历史上下文

use serde_json::Value;

use crate::engine::{Match, RuleSet};

/// 与 CPR 默认解压后的 Responses 请求正文上限保持一致。
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

pub fn inspect_json(rules: &RuleSet, body: &[u8]) -> Result<Option<Match>, String> {
    inspect_json_with_limit(rules, body, MAX_REQUEST_BYTES)
}

/// 使用更小的正文及文本上限检查完整请求；不能提升 CPR 默认的 64 MiB 上限。
pub fn inspect_json_with_limit(
    rules: &RuleSet,
    body: &[u8],
    maximum_bytes: usize,
) -> Result<Option<Match>, String> {
    let maximum_bytes = maximum_bytes.min(MAX_REQUEST_BYTES);
    if body.is_empty() {
        return Err("Request body is empty.".into());
    }
    if body.len() > maximum_bytes {
        return Err(format!(
            "Request exceeds the {maximum_bytes}-byte keyword inspection limit."
        ));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "Request must be valid JSON within the supported nesting limit.".to_owned())?;
    if !value.is_object() {
        return Err("Request must be a JSON object.".into());
    }
    inspect_value(rules, &value, maximum_bytes)
}

fn inspect_value(
    rules: &RuleSet,
    value: &Value,
    maximum_bytes: usize,
) -> Result<Option<Match>, String> {
    match value {
        Value::String(text) => rules.check_with_limit(text, maximum_bytes),
        Value::Array(values) => {
            let mut consecutive_text = String::new();
            for value in values {
                if let Some(text) = text_block(value) {
                    if consecutive_text.len().saturating_add(text.len()) > maximum_bytes {
                        return Err(
                            "Combined message text exceeds the keyword inspection limit.".into(),
                        );
                    }
                    consecutive_text.push_str(text);
                } else if !consecutive_text.is_empty() {
                    if let Some(matched) =
                        rules.check_with_limit(&consecutive_text, maximum_bytes)?
                    {
                        return Ok(Some(matched));
                    }
                    consecutive_text.clear();
                }
                if let Some(matched) = inspect_value(rules, value, maximum_bytes)? {
                    return Ok(Some(matched));
                }
            }
            rules.check_with_limit(&consecutive_text, maximum_bytes)
        }
        Value::Object(values) => {
            for value in values.values() {
                if let Some(matched) = inspect_value(rules, value, maximum_bytes)? {
                    return Ok(Some(matched));
                }
            }
            Ok(None)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(None),
    }
}

fn text_block(value: &Value) -> Option<&str> {
    match value.get("type").and_then(Value::as_str) {
        Some("text" | "input_text" | "output_text") => value.get("text").and_then(Value::as_str),
        _ => None,
    }
}
