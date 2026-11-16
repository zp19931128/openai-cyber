//! 注册仅管理员可访问的拦截日志页面与查询接口

use std::sync::Arc;

use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
    call::management::{
        ManagementPage, ManagementRegistration, ManagementRequest, ManagementResource,
        ManagementResponse, ManagementRoute,
    },
    client::{TypedCall, TypedReply},
};
use serde::Serialize;
use serde_json::json;

use crate::audit::AuditStore;

pub(crate) fn registration() -> ManagementRegistration {
    ManagementRegistration {
        routes: vec![ManagementRoute {
            method: "GET".into(),
            path: "api/audit".into(),
            request_content_types: Vec::new(),
            response_content_types: vec!["application/json".into()],
        }],
        resources: ["web/index.html", "web/app.js", "web/app.css"]
            .into_iter()
            .map(|path| ManagementResource {
                path: path.into(),
                public: false,
            })
            .collect(),
        pages: vec![ManagementPage {
            id: "audit".into(),
            title: "拦截日志".into(),
            description: Some("查看命中规则与本次请求的脱敏上下文".into()),
            entry: "web/index.html".into(),
            icon: None,
        }],
        callbacks: Vec::new(),
    }
}

pub(crate) async fn handle(
    store: Arc<AuditStore>,
    call: TypedCall<ManagementRequest>,
) -> Result<TypedReply<ManagementResponse>, PluginFault> {
    if call.request.method != "GET" || call.request.path != "api/audit" {
        return reply(
            404,
            &json!({"error":{"code":"not_found","message":"未找到插件管理接口"}}),
        );
    }
    if !call.request.query.is_empty() || !call.payload.is_empty() {
        return reply(
            400,
            &json!({"error":{"code":"invalid_request","message":"日志查询不接受查询参数或请求正文"}}),
        );
    }
    match store.snapshot(&call.host).await {
        Ok(snapshot) => reply(200, &snapshot),
        Err(_) => reply(
            503,
            &json!({"error":{"code":"audit_unavailable","message":"拦截日志读取失败"}}),
        ),
    }
}

fn reply(
    status: u16,
    value: &impl Serialize,
) -> Result<TypedReply<ManagementResponse>, PluginFault> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| PluginFault::new(ErrorCode::Fault, "拦截日志响应编码失败"))?;
    Ok(TypedReply::new(ManagementResponse {
        status,
        content_type: "application/json".into(),
        headers: Vec::new(),
    })
    .with_payload(payload))
}
