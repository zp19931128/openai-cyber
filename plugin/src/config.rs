//! 分离插件审计选项与离线工具共用的规则配置

use cpr_keyword_guard::engine::GuardConfig;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AuditConfig {
    pub capture_context: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            capture_context: true,
        }
    }
}

pub(crate) fn parse(mut value: Value) -> Result<(GuardConfig, AuditConfig), &'static str> {
    let object = value
        .as_object_mut()
        .ok_or("Invalid keyword guard configuration.")?;
    let audit = object
        .remove("audit")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| "Invalid audit configuration.")?
        .unwrap_or_default();
    let rules =
        serde_json::from_value(value).map_err(|_| "Invalid keyword guard configuration.")?;
    Ok((rules, audit))
}

#[cfg(test)]
mod tests {
    use super::parse;
    use serde_json::json;

    #[test]
    fn existing_configuration_and_audit_opt_out_are_supported() {
        assert!(parse(json!({})).unwrap().1.capture_context);
        assert!(
            !parse(json!({"audit": {"capture_context": false}}))
                .unwrap()
                .1
                .capture_context
        );
    }

    #[test]
    fn invalid_or_unknown_options_fail_instead_of_silently_enabling_capture() {
        for value in [
            json!({"audit": null}),
            json!({"audit": {"capture_context": "false"}}),
            json!({"audit": {"unexpected": true}}),
            json!({"unknown": true}),
        ] {
            assert!(parse(value).is_err());
        }
    }
}
