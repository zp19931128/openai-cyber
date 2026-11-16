//! 用双语语料验证内置规则的恶意请求拦截与正常请求边界

use cpr_keyword_guard::engine::{GuardConfig, RuleSet};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    text: String,
    deny: bool,
}

#[test]
fn bilingual_builtin_corpus() {
    let cases: Vec<Case> = serde_json::from_str(include_str!("corpus.json")).unwrap();
    let rules = RuleSet::load(GuardConfig::default()).unwrap();
    for case in cases {
        assert_eq!(
            rules.check(&case.text).unwrap().is_some(),
            case.deny,
            "Unexpected decision for {}",
            case.name
        );
    }
}
