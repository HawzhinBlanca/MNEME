//! Source-level guards for core parser error taxonomy.

use std::fs;
use std::path::{Path, PathBuf};

const PARSER_SOURCES: &[&str] = &[
    "accountability.rs",
    "context.rs",
    "dcbor.rs",
    "embedding.rs",
    "enclave.rs",
    "hex.rs",
    "object.rs",
    "object_path.rs",
    "output.rs",
];

#[test]
fn parser_error_taxonomy_sites_are_audited() {
    let mut violations = Vec::new();

    for path in parser_sources() {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?");
        let source = fs::read_to_string(&path).expect("read mneme-core source");
        let mut current_fn = None;
        for (idx, line) in production_lines(&source).enumerate() {
            if let Some(fn_name) = function_name(line) {
                current_fn = Some(fn_name.to_owned());
            }
            if line.contains("MnemeError::")
                && !is_allowed_parser_error_site(line, current_fn.as_deref())
            {
                violations.push(format!("{file_name}:{}:{}", idx + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "direct core parser MnemeError sites must stay behind failure classifiers:\n{}",
        violations.join("\n")
    );
}

fn parser_sources() -> Vec<PathBuf> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    PARSER_SOURCES
        .iter()
        .map(|path| src_dir.join(path))
        .collect()
}

fn production_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .split_once("#[cfg(test)]")
        .map_or(source, |(production, _tests)| production)
        .lines()
}

fn function_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix("pub(crate) ").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
    let signature = trimmed.strip_prefix("fn ")?;
    signature.split(['(', '<']).next()
}

fn is_allowed_parser_error_site(line: &str, current_fn: Option<&str>) -> bool {
    if line.trim_start().starts_with("//") {
        return true;
    }

    current_fn.is_some_and(|fn_name| fn_name.ends_with("_failure_to_mneme"))
}
