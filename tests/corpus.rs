//! 用双语语料验证内置规则的恶意请求拦截与正常请求边界

use cpr_keyword_guard::engine::{GuardConfig, RuleSet};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Case {
    name: String,
    text: String,
    deny: bool,
}

#[test]
fn bilingual_builtin_corpus() {
    let cases: Vec<Case> = serde_json::from_str(include_str!("corpus.json")).unwrap();
    // 语料覆盖所有内置规则，默认关闭规则的开关语义由 engine 测试单独验证。
    let builtins: Value = serde_json::from_str(include_str!("../rules/builtin.json")).unwrap();
    let rules = RuleSet::load(GuardConfig {
        enabled_builtin_ids: builtins["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["id"].as_str().unwrap().to_owned())
            .collect(),
        ..GuardConfig::default()
    })
    .unwrap();
    for case in cases {
        assert_eq!(
            rules.check(&case.text).unwrap().is_some(),
            case.deny,
            "Unexpected decision for {}",
            case.name
        );
    }
}
