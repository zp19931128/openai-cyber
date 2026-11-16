//! 注册仅管理员可访问的规则管理和拦截日志页面接口

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

use crate::{audit::AuditStore, rules::RulesService};

pub(crate) fn registration() -> ManagementRegistration {
    ManagementRegistration {
        routes: [
            ("GET", "api/audit"),
            ("GET", "api/rules"),
            ("POST", "api/rules/validate"),
            ("POST", "api/rules/test"),
            ("POST", "api/rules/save"),
        ]
        .into_iter()
        .map(|(method, path)| ManagementRoute {
            method: method.into(),
            path: path.into(),
            request_content_types: if method == "POST" {
                vec!["application/json".into()]
            } else {
                Vec::new()
            },
            response_content_types: vec!["application/json".into()],
        })
        .collect(),
        resources: ["web/index.html", "web/app.js", "web/app.css"]
            .into_iter()
            .map(|path| ManagementResource {
                path: path.into(),
                public: false,
            })
            .collect(),
        pages: vec![ManagementPage {
            id: "audit".into(),
            title: "规则与拦截日志".into(),
            description: Some("配置内置与补充规则，测试命中效果并查看拦截上下文".into()),
            entry: "web/index.html".into(),
            icon: None,
        }],
        callbacks: Vec::new(),
    }
}

pub(crate) async fn handle(
    store: Arc<AuditStore>,
    rules: Arc<RulesService>,
    call: TypedCall<ManagementRequest>,
) -> Result<TypedReply<ManagementResponse>, PluginFault> {
    if !rules.matches_instance(&call.context.instance_id) {
        return reply(
            403,
            &json!({"error":{"code":"forbidden","message":"管理调用的插件实例不匹配"}}),
        );
    }
    if call.request.path.starts_with("api/rules") {
        if !call.request.query.is_empty()
            || (call.request.method == "GET" && !call.payload.is_empty())
            || (call.request.method == "POST"
                && call.request.content_type.as_deref() != Some("application/json"))
        {
            return reply(
                400,
                &json!({"error":{"code":"invalid_request","message":"规则管理接口不接受查询参数且仅支持 JSON 正文"}}),
            );
        }
        return match rules
            .handle(
                &call.host,
                &call.request.method,
                &call.request.path,
                &call.payload,
            )
            .await
        {
            Ok(response) => reply(200, &response),
            Err(error) => reply(error.status, &error.body),
        };
    }
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
        .map_err(|_| PluginFault::new(ErrorCode::Fault, "插件管理响应编码失败"))?;
    Ok(TypedReply::new(ManagementResponse {
        status,
        content_type: "application/json".into(),
        headers: Vec::new(),
    })
    .with_payload(payload))
}
