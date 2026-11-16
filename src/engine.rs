//! 编译内置与补充规则并在有界短句中匹配，不推断请求的政策合规性

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

const SCHEMA_VERSION: u32 = 1;
const MAX_RULES: usize = 1024;
const MAX_GROUPS: usize = 16;
const MAX_TERMS_PER_GROUP: usize = 64;
const MAX_TOTAL_TERMS: usize = 8192;
const MAX_TERM_CHARS: usize = 256;
const MAX_SPAN_CHARS: usize = 4096;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGEX_BYTES: usize = 2048;

fn schema_version() -> u32 {
    SCHEMA_VERSION
}

fn default_span() -> usize {
    160
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub disabled_builtin_ids: Vec<String>,
    #[serde(default)]
    pub extra_keywords: Vec<String>,
    #[serde(default)]
    pub extra_regexes: Vec<String>,
    #[serde(default)]
    pub custom_rules: Vec<Rule>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            disabled_builtin_ids: Vec::new(),
            extra_keywords: Vec::new(),
            extra_regexes: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub description: String,
    pub all_groups: Vec<Vec<String>>,
    #[serde(default = "default_span")]
    pub max_span_chars: usize,
    #[serde(default)]
    pub word_boundaries: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Match {
    pub rule_id: String,
    pub category: String,
    pub policy_version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Builtins {
    schema_version: u32,
    policy_version: String,
    rules: Vec<Rule>,
}

pub struct RuleSet {
    policy_version: String,
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    id: String,
    category: String,
    matcher: Matcher,
}

enum Matcher {
    Groups {
        groups: Vec<Vec<Term>>,
        max_span_chars: usize,
        word_boundaries: bool,
    },
    Regex(Regex),
}

struct Term {
    text: String,
    chars: usize,
}

impl RuleSet {
    pub fn load(config: GuardConfig) -> Result<Self, String> {
        if config.schema_version != SCHEMA_VERSION {
            return Err("Unsupported configuration schema_version; expected 1.".into());
        }
        let builtins: Builtins = serde_json::from_str(include_str!("../rules/builtin.json"))
            .map_err(|_| "The embedded rule dictionary is invalid.".to_owned())?;
        if builtins.schema_version != SCHEMA_VERSION || builtins.policy_version.is_empty() {
            return Err("The embedded rule dictionary version is invalid.".into());
        }
        let total = builtins
            .rules
            .len()
            .saturating_add(config.custom_rules.len())
            .saturating_add(config.extra_keywords.len())
            .saturating_add(config.extra_regexes.len());
        if total > MAX_RULES {
            return Err(format!("Too many rules; the maximum is {MAX_RULES}."));
        }

        let builtin_ids: HashSet<&str> =
            builtins.rules.iter().map(|rule| rule.id.as_str()).collect();
        let mut disabled = HashSet::new();
        for id in &config.disabled_builtin_ids {
            if !builtin_ids.contains(id.as_str()) {
                return Err(format!("Unknown disabled builtin rule ID: {id}."));
            }
            if !disabled.insert(id.as_str()) {
                return Err(format!("Duplicate disabled builtin rule ID: {id}."));
            }
        }

        let mut ids = HashSet::new();
        let mut rules = Vec::with_capacity(total);
        let mut term_count = 0;
        for rule in &builtins.rules {
            let compiled = compile_rule(rule, &mut ids, &mut term_count)?;
            if !disabled.contains(rule.id.as_str()) {
                rules.push(compiled);
            }
        }
        for rule in &config.custom_rules {
            rules.push(compile_rule(rule, &mut ids, &mut term_count)?);
        }
        for (index, keyword) in config.extra_keywords.iter().enumerate() {
            let rule = Rule {
                id: format!("custom.keyword.{}", index + 1),
                category: "custom_keyword".into(),
                description: "用户补充关键词".into(),
                all_groups: vec![vec![keyword.clone()]],
                max_span_chars: MAX_TERM_CHARS,
                word_boundaries: false,
            };
            rules.push(compile_rule(&rule, &mut ids, &mut term_count)?);
        }
        for (index, pattern) in config.extra_regexes.iter().enumerate() {
            let id = format!("custom.regex.{}", index + 1);
            insert_id(&id, &mut ids)?;
            if pattern.is_empty() || pattern.len() > MAX_REGEX_BYTES {
                return Err(format!(
                    "Regex {id} must contain 1 to {MAX_REGEX_BYTES} bytes."
                ));
            }
            let regex = RegexBuilder::new(pattern)
                .case_insensitive(true)
                .nest_limit(32)
                .size_limit(256 * 1024)
                .dfa_size_limit(2 * 1024 * 1024)
                .build()
                .map_err(|_| format!("Regex {id} is invalid or exceeds the complexity limit."))?;
            if regex.is_match("") {
                return Err(format!("Regex {id} must not match an empty string."));
            }
            rules.push(CompiledRule {
                id,
                category: "custom_regex".into(),
                matcher: Matcher::Regex(regex),
            });
        }
        Ok(Self {
            policy_version: builtins.policy_version,
            rules,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn check(&self, text: &str) -> Result<Option<Match>, String> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(format!(
                "Text exceeds the {MAX_TEXT_BYTES}-byte inspection limit."
            ));
        }
        let text = normalize(text);
        if text.len() > MAX_TEXT_BYTES {
            return Err(format!(
                "Normalized text exceeds the {MAX_TEXT_BYTES}-byte inspection limit."
            ));
        }
        for rule in &self.rules {
            for clause in text
                .split(is_clause_boundary)
                .filter(|part| !part.is_empty())
            {
                let matched = match &rule.matcher {
                    Matcher::Groups {
                        groups,
                        max_span_chars,
                        word_boundaries,
                    } => matches_groups(clause, groups, *max_span_chars, *word_boundaries),
                    Matcher::Regex(regex) => regex.is_match(clause),
                };
                if matched {
                    return Ok(Some(Match {
                        rule_id: rule.id.clone(),
                        category: rule.category.clone(),
                        policy_version: self.policy_version.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }
}

fn compile_rule(
    rule: &Rule,
    ids: &mut HashSet<String>,
    total_terms: &mut usize,
) -> Result<CompiledRule, String> {
    insert_id(&rule.id, ids)?;
    if !valid_identifier(&rule.category, 64) {
        return Err(format!("Rule {} has an invalid category.", rule.id));
    }
    if rule.description.trim().is_empty() || rule.description.len() > 2048 {
        return Err(format!(
            "Rule {} must have a nonempty description of at most 2048 bytes.",
            rule.id
        ));
    }
    if rule.max_span_chars == 0 || rule.max_span_chars > MAX_SPAN_CHARS {
        return Err(format!(
            "Rule {} max_span_chars must be between 1 and {MAX_SPAN_CHARS}.",
            rule.id
        ));
    }
    if rule.all_groups.is_empty() || rule.all_groups.len() > MAX_GROUPS {
        return Err(format!(
            "Rule {} must have 1 to {MAX_GROUPS} groups.",
            rule.id
        ));
    }
    let mut groups = Vec::with_capacity(rule.all_groups.len());
    for source in &rule.all_groups {
        if source.is_empty() || source.len() > MAX_TERMS_PER_GROUP {
            return Err(format!(
                "Rule {} groups must have 1 to {MAX_TERMS_PER_GROUP} terms.",
                rule.id
            ));
        }
        let mut terms = Vec::with_capacity(source.len());
        let mut seen_terms = HashSet::new();
        for source_term in source {
            if source_term.len() > 4096 {
                return Err(format!("Rule {} contains an oversized term.", rule.id));
            }
            let text = normalize(source_term);
            let chars = text.chars().count();
            if text.trim().is_empty() || chars > MAX_TERM_CHARS || chars > rule.max_span_chars {
                return Err(format!(
                    "Rule {} contains an empty or oversized term.",
                    rule.id
                ));
            }
            if text.chars().any(is_clause_boundary) {
                return Err(format!(
                    "Rule {} contains a term crossing a sentence boundary.",
                    rule.id
                ));
            }
            if seen_terms.insert(text.clone()) {
                terms.push(Term { text, chars });
                *total_terms = total_terms.saturating_add(1);
            }
        }
        if *total_terms > MAX_TOTAL_TERMS {
            return Err(format!(
                "Too many rule terms; the maximum is {MAX_TOTAL_TERMS}."
            ));
        }
        groups.push(terms);
    }
    Ok(CompiledRule {
        id: rule.id.clone(),
        category: rule.category.clone(),
        matcher: Matcher::Groups {
            groups,
            max_span_chars: rule.max_span_chars,
            word_boundaries: rule.word_boundaries,
        },
    })
}

fn insert_id(id: &str, ids: &mut HashSet<String>) -> Result<(), String> {
    if !valid_identifier(id, 128) {
        return Err(
            "Rule IDs must contain 1 to 128 ASCII letters, digits, dots, hyphens or underscores."
                .into(),
        );
    }
    if !ids.insert(id.to_owned()) {
        return Err(format!("Duplicate rule ID: {id}."));
    }
    Ok(())
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn normalize(text: &str) -> String {
    text.nfkc()
        .filter(|character| {
            !matches!(
                character,
                '\u{00ad}' | '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}'
            )
        })
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_clause_boundary(character: char) -> bool {
    matches!(
        character,
        '.' | ';' | '!' | '?' | '\n' | '\r' | '\u{2028}' | '\u{2029}' | '。' | '；' | '！' | '？'
    )
}

struct TermScan<'a> {
    clause: &'a str,
    term: &'a Term,
    group: usize,
    offset: usize,
    word_boundaries: bool,
}

impl TermScan<'_> {
    fn next_hit(&mut self) -> Option<(usize, usize)> {
        while let Some(relative) = self.clause[self.offset..].find(&self.term.text) {
            let start = self.offset + relative;
            let end = start + self.term.text.len();
            // 从命中起点的下一个字符继续，保留重叠命中以免漏掉最短窗口
            self.offset = start + self.clause[start..].chars().next()?.len_utf8();
            if !self.word_boundaries
                || (!self.clause[..start]
                    .chars()
                    .next_back()
                    .is_some_and(is_word_character)
                    && !self.clause[end..]
                        .chars()
                        .next()
                        .is_some_and(is_word_character))
            {
                return Some((start, end));
            }
        }
        None
    }
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

fn matches_groups(clause: &str, groups: &[Vec<Term>], max_span: usize, boundaries: bool) -> bool {
    let mut scans = Vec::new();
    let mut hits = BinaryHeap::new();
    for (group, terms) in groups.iter().enumerate() {
        let mut found_group = false;
        for term in terms {
            let mut scan = TermScan {
                clause,
                term,
                group,
                offset: 0,
                word_boundaries: boundaries,
            };
            if let Some((start, end)) = scan.next_hit() {
                hits.push(Reverse((end, start, scans.len())));
                scans.push(scan);
                found_group = true;
            }
        }
        if !found_group {
            return false;
        }
    }

    let mut latest_starts: Vec<Option<usize>> = vec![None; groups.len()];
    let mut seen = 0;
    let mut processed_byte_end = 0;
    let mut processed_char_end = 0;
    while let Some(Reverse((end, _, index))) = hits.pop() {
        // 堆按结束位置推进，只扫描一次字符偏移，不按请求长度分配命中列表
        processed_char_end += clause[processed_byte_end..end].chars().count();
        processed_byte_end = end;
        let scan = &mut scans[index];
        let start = processed_char_end - scan.term.chars;
        let latest = &mut latest_starts[scan.group];
        if latest.is_none() {
            seen += 1;
        }
        *latest = Some(latest.map_or(start, |previous| previous.max(start)));
        if seen == groups.len()
            && latest_starts
                .iter()
                .flatten()
                .min()
                .is_some_and(|minimum| processed_char_end - minimum <= max_span)
        {
            return true;
        }
        if let Some((start, end)) = scan.next_hit() {
            hits.push(Reverse((end, start, index)));
        }
    }
    false
}
