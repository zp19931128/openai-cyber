//! 校验规则配置并通过标准输入离线检查文本，不输出原始内容

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use cpr_keyword_guard::engine::{GuardConfig, RuleSet};
use serde_json::json;

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!(
                "{}",
                json!({"error": {"code": "keyword_guard_error", "message": message}})
            );
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());
    let mut config_path = None;
    while let Some(arg) = args.next() {
        if arg != "--config" || config_path.is_some() {
            return Err("Expected one optional --config PATH argument.".into());
        }
        config_path = Some(args.next().ok_or("Missing --config path.")?);
    }
    if command == "help" || command == "--help" || command == "-h" {
        println!(
            "cpr-keyword-guard check [--config PATH] < prompt.txt\ncpr-keyword-guard validate [--config PATH]\ncpr-keyword-guard export\nExit codes: 0 = no match or valid configuration, 2 = blocked, 1 = error."
        );
        return Ok(0);
    }
    if command == "export" {
        if config_path.is_some() {
            return Err("Export does not accept --config.".into());
        }
        print!("{}", include_str!("../rules/builtin.json"));
        return Ok(0);
    }
    if command != "check" && command != "validate" {
        return Err("Unknown command. Use check, validate, export, or --help.".into());
    }
    let config = match config_path {
        Some(path) => {
            let file = File::open(Path::new(&path))
                .map_err(|_| "Cannot open the configuration file.".to_owned())?;
            let text = read_bounded(file)?;
            serde_json::from_str(&text).map_err(|_| {
                "The configuration must be valid JSON with supported fields.".to_owned()
            })?
        }
        None => GuardConfig::default(),
    };
    let rules = RuleSet::load(config)?;
    if command == "validate" {
        println!(
            "{}",
            json!({"valid": true, "rule_count": rules.rule_count()})
        );
        return Ok(0);
    }
    let text = read_bounded(io::stdin().lock())?;
    match rules.check(&text)? {
        Some(matched) => {
            println!("{}", json!({"decision": "deny", "match": matched}));
            Ok(2)
        }
        None => {
            println!("{}", json!({"decision": "no_match"}));
            Ok(0)
        }
    }
}

fn read_bounded(reader: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read the input.".to_owned())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("Input exceeds the 2 MiB inspection limit.".into());
    }
    String::from_utf8(bytes).map_err(|_| "Input must be valid UTF-8 text.".into())
}
