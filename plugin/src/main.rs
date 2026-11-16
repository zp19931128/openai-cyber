//! 在 CPR 每轮模型请求进入上游前执行关键词检查

mod audit;
mod config;
mod management;

use std::{sync::Arc, time::Duration};

use cpr_keyword_guard::{engine::RuleSet, request::inspect_json};
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
    let (config, audit_config) = config::parse(session.handshake().configuration.clone())?;
    let rules = Arc::new(RuleSet::load(config)?);
    let audit = Arc::new(audit::AuditStore::new(audit_config.capture_context));
    let middleware_audit = Arc::clone(&audit);
    let plugin = PluginBuilder::from_json(include_bytes!("../plugin.json"))?
        .middleware(move |call: RequestCall| {
            let rules = Arc::clone(&rules);
            let audit = Arc::clone(&middleware_audit);
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
                        let recorded = tokio::time::timeout(
                            Duration::from_millis(400),
                            audit.append(&call.host, &call.request, &details, message),
                        )
                        .await
                        .unwrap_or(false);
                        if !recorded {
                            audit.record_failure();
                        }
                        let log = LogRequest {
                            event: "keyword_guard.denied".into(),
                            level: LogLevel::Warn,
                            fields: std::collections::BTreeMap::from([
                                ("request_id".into(), json!(call.request.head.request_id)),
                                ("policy".into(), details.clone()),
                                ("audit_recorded".into(), json!(recorded)),
                            ]),
                        };
                        if let Ok(params) = serde_json::to_value(log) {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(100),
                                call.host.call(host::LOG, params, Vec::new()),
                            )
                            .await;
                        }
                        let mut fault = PluginFault::new(ErrorCode::Rejected, message);
                        fault.http_status = Some(status);
                        fault.details = Some(details);
                        Err(fault)
                    }
                }
            }
        })?
        .management(management::registration(), move |call| {
            management::handle(Arc::clone(&audit), call)
        })?
        .build()?;
    session.run(plugin).await?;
    Ok(())
}
