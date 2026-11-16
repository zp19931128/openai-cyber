//! 检查本轮 JSON 请求中的字符串，不修改正文或推断历史上下文

use serde_json::Value;

use crate::engine::{Match, RuleSet};

const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

pub fn inspect_json(rules: &RuleSet, body: &[u8]) -> Result<Option<Match>, String> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err("Request exceeds the 2 MiB keyword inspection limit.".into());
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "Request must be valid JSON within the supported nesting limit.".to_owned())?;
    if !value.is_object() {
        return Err("Request must be a JSON object.".into());
    }
    inspect_value(rules, &value)
}

fn inspect_value(rules: &RuleSet, value: &Value) -> Result<Option<Match>, String> {
    match value {
        Value::String(text) => rules.check(text),
        Value::Array(values) => {
            let mut consecutive_text = String::new();
            for value in values {
                if let Some(text) = text_block(value) {
                    if consecutive_text.len().saturating_add(text.len()) > MAX_REQUEST_BYTES {
                        return Err(
                            "Combined message text exceeds the keyword inspection limit.".into(),
                        );
                    }
                    consecutive_text.push_str(text);
                } else if !consecutive_text.is_empty() {
                    if let Some(matched) = rules.check(&consecutive_text)? {
                        return Ok(Some(matched));
                    }
                    consecutive_text.clear();
                }
                if let Some(matched) = inspect_value(rules, value)? {
                    return Ok(Some(matched));
                }
            }
            rules.check(&consecutive_text)
        }
        Value::Object(values) => {
            for value in values.values() {
                if let Some(matched) = inspect_value(rules, value)? {
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
