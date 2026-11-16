//! 在 CPR 每轮模型请求进入上游前执行关键词检查

use std::sync::Arc;

use cpr_keyword_guard::{
    engine::{GuardConfig, RuleSet},
    request::inspect_json,
};
use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
    call::host::{self, LogLevel, LogRequest},
    client::{PluginBuilder, PluginSession, RequestCall, SessionConfig},
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = PluginSession::accept(
        tokio::io::stdin(),
        tokio::io::stdout(),
        SessionConfig::default(),
    )
    .await?;
    let config: GuardConfig = serde_json::from_value(session.handshake().configuration.clone())
        .map_err(|_| "Invalid keyword guard configuration.")?;
    let rules = Arc::new(RuleSet::load(config)?);
    let plugin = PluginBuilder::from_json(include_bytes!("../plugin.json"))?
        .middleware(move |call: RequestCall| {
            let rules = Arc::clone(&rules);
            async move {
                match inspect_json(&rules, &call.request.body) {
                    Ok(None) => call.next.run(call.request).await,
                    result => {
                        let (message, status, details) = match result {
                            Ok(Some(matched)) => (
                                "Request blocked by keyword policy.",
                                403,
                                json!({"code": "keyword_policy_blocked", "rule_id": matched.rule_id, "category": matched.category, "policy_version": matched.policy_version}),
                            ),
                            Err(_) => (
                                "Request could not be inspected by keyword policy.",
                                400,
                                json!({"code": "keyword_inspection_failed"}),
                            ),
                            Ok(None) => unreachable!(),
                        };
                        let log = LogRequest {
                            event: "keyword_guard.denied".into(),
                            level: LogLevel::Warn,
                            fields: std::collections::BTreeMap::from([
                                ("request_id".into(), json!(call.request.head.request_id)),
                                ("policy".into(), details.clone()),
                            ]),
                        };
                        if let Ok(params) = serde_json::to_value(log) {
                            let _ = call.host.call(host::LOG, params, Vec::new()).await;
                        }
                        let mut fault = PluginFault::new(ErrorCode::Rejected, message);
                        fault.http_status = Some(status);
                        fault.details = Some(details);
                        Err(fault)
                    }
                }
            }
        })?
        .build()?;
    session.run(plugin).await?;
    Ok(())
}
