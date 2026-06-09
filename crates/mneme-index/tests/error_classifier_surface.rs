//! Regression: production fail-closed errors in `mneme-index` must stay routed
//! through typed classifier surfaces instead of ad hoc direct rejection sites.

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_mneme_error_sites_are_audited() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();

    for source in rust_sources(&src_dir) {
        let text = fs::read_to_string(&source).expect("read mneme-index source");
        let file_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?");
        let mut current_fn = None;
        for (idx, line) in production_lines(&text).enumerate() {
            if let Some(fn_name) = function_name(line) {
                current_fn = Some(fn_name.to_owned());
            }
            if line.contains("MnemeError::")
                && !is_allowed_mneme_error_site(file_name, line, current_fn.as_deref())
            {
                violations.push(format!("{file_name}:{}:{}", idx + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "direct production MnemeError sites must stay behind classifiers/adapters:\n{}",
        violations.join("\n")
    );
}

fn rust_sources(src_dir: &Path) -> Vec<PathBuf> {
    let mut sources = fs::read_dir(src_dir)
        .expect("read mneme-index src dir")
        .map(|entry| entry.expect("read mneme-index src entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect::<Vec<_>>();
    sources.sort();
    sources
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
    let trimmed = trimmed.strip_prefix("async ").unwrap_or(trimmed);
    let signature = trimmed.strip_prefix("fn ")?;
    signature.split(['(', '<']).next()
}

fn is_allowed_mneme_error_site(file_name: &str, line: &str, current_fn: Option<&str>) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return true;
    }

    if current_fn.is_some_and(|fn_name| fn_name.ends_with("_failure_to_mneme")) {
        return true;
    }

    matches!(
        (file_name, current_fn),
        ("key_index_load.rs", Some("io_err"))
            | ("semantic_load.rs", Some("io_err"))
            | ("error.rs", Some("from"))
    )
}
