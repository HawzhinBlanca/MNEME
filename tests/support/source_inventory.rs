#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub(crate) fn rust_source_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_source_files(dir, &mut files);
    files.sort();
    files
}

pub(crate) fn test_function_names(source: &str) -> Vec<String> {
    test_function_names_with_lines(source)
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

pub(crate) fn test_function_names_with_lines(source: &str) -> Vec<(usize, String)> {
    let mut names = Vec::new();
    let mut saw_test_attr = false;
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "#[test]" {
            saw_test_attr = true;
            continue;
        }

        if !saw_test_attr {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("fn ") {
            if let Some((name, _)) = rest.split_once('(') {
                names.push((line_index + 1, name.to_string()));
            }
        }
        if !trimmed.is_empty() && !trimmed.starts_with("#[") {
            saw_test_attr = false;
        }
    }
    names
}

pub(crate) fn test_functions_with_prefixes(source: &str, prefixes: &[&str]) -> Vec<String> {
    test_function_names(source)
        .into_iter()
        .filter(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
        .collect()
}

pub(crate) fn source_contains_test_fn(source: &str, name: &str) -> bool {
    test_functions_with_prefixes(source, &[name])
        .iter()
        .any(|candidate| candidate == name)
}

pub(crate) fn assert_no_local_source_scan_helpers(source_name: &str, source: &str) {
    let local_helpers = local_function_names(source)
        .into_iter()
        .filter(|name| is_source_scan_helper(name))
        .collect::<Vec<_>>();
    assert!(
        local_helpers.is_empty(),
        "{source_name} must use tests/support/source_inventory.rs for source parsing; \
         local helper definitions found: {local_helpers:?}"
    );
}

pub(crate) fn assert_no_local_source_inventory_helpers(source_name: &str, source: &str) {
    assert_no_local_source_scan_helpers(source_name, source);
}

pub(crate) fn test_generator_macro_names(source: &str) -> Vec<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut names = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("macro_rules!") else {
            continue;
        };
        let macro_name = rest.trim().trim_end_matches('{').trim();
        if macro_name.is_empty() {
            continue;
        }

        let emits_test = lines[index..]
            .iter()
            .take_while(|body_line| body_line.trim() != "}")
            .any(|body_line| body_line.contains("#[test]"));
        if emits_test {
            names.push(macro_name.to_string());
        }
    }
    names
}

pub(crate) fn source_between_markers<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing start marker {start}"));
    let (section, _) = tail
        .split_once(end)
        .unwrap_or_else(|| panic!("missing end marker {end}"));
    section
}

pub(crate) fn rust_function_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix("pub(crate) ").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
    let signature = trimmed.strip_prefix("fn ")?;
    signature.split(['(', '<']).next()
}

pub(crate) fn rust_function_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(rust_function_name)
        .map(str::to_owned)
        .collect()
}

fn local_function_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("fn "))
        .filter_map(|rest| rest.split(['(', '<']).next().map(str::to_string))
        .collect()
}

fn collect_rust_source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }

    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("source dir entry").path();
        if path.is_dir() {
            collect_rust_source_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn is_source_scan_helper(name: &str) -> bool {
    matches!(
        name,
        "test_function_names"
            | "test_function_names_with_lines"
            | "test_functions_with_prefix"
            | "test_functions_with_prefixes"
            | "source_contains_test_fn"
            | "test_generator_macro_names"
            | "source_between_markers"
            | "function_name"
            | "rust_function_name"
            | "rust_function_names"
            | "scan_test_fn_names_for_legacy_head_verify"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "local helper definitions found")]
    fn shared_helper_guard_rejects_local_inventory_parsers() {
        let source = concat!(
            "use source_inventory::test_function_names;\n",
            "fn test_functions_with_prefix(source: &str, prefix: &str) {}\n",
        );

        assert_no_local_source_scan_helpers("bad.rs", source);
    }

    #[test]
    fn shared_helper_guard_allows_imports_and_calls() {
        let source = concat!(
            "use source_inventory::{source_contains_test_fn, test_functions_with_prefixes};\n",
            "#[test]\n",
            "fn inventory_source_scan_counts_only_test_functions() {\n",
            "    test_functions_with_prefixes(\"\", &[\"tamper_\"]);\n",
            "}\n",
        );

        assert_no_local_source_scan_helpers("ok.rs", source);
    }

    #[test]
    #[should_panic(expected = "local helper definitions found")]
    fn shared_helper_guard_rejects_classifier_source_parsers() {
        let source = concat!(
            "use source_inventory::source_between_markers;\n",
            "fn source_between_markers<'a>(source: &'a str, start: &str, end: &str) -> &'a str { source }\n",
            "fn function_name(line: &str) -> Option<&str> { None }\n",
        );

        assert_no_local_source_scan_helpers("bad-classifier.rs", source);
    }

    #[test]
    #[should_panic(expected = "local helper definitions found")]
    fn shared_helper_guard_rejects_adoption_source_parsers() {
        let source = concat!(
            "use source_inventory::test_function_names;\n",
            "fn scan_test_fn_names_for_legacy_head_verify(path: &Path, hits: &mut Vec<String>) {}\n",
        );

        assert_no_local_source_scan_helpers("bad-adoption.rs", source);
    }

    #[test]
    fn shared_helpers_extract_source_sections_and_function_names() {
        let source = "aaa fn start() {} target fn end() {} zzz";
        assert_eq!(
            source_between_markers(source, "fn start()", "fn end()"),
            " {} target "
        );
        assert_eq!(rust_function_name("pub fn alpha<T>() {}"), Some("alpha"));
        assert_eq!(rust_function_name("pub(crate) fn beta() {}"), Some("beta"));
        assert_eq!(
            rust_function_names("fn start() {}\npub fn alpha<T>() {}\npub(crate) fn beta() {}\n"),
            vec!["start".to_string(), "alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn shared_helpers_extract_test_function_names_with_lines() {
        const SOURCE: &str = concat!(
            "fn helper() {}\n",
            "#[test]\n",
            "fn first_case() {}\n",
            "#[test]\n",
            "#[ignore]\n",
            "fn ignored_case() {}\n",
        );

        assert_eq!(
            test_function_names_with_lines(SOURCE),
            vec![
                (3, "first_case".to_string()),
                (6, "ignored_case".to_string()),
            ]
        );
    }

    #[test]
    fn shared_helpers_find_nested_rust_source_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lib.rs"), "").expect("write lib");
        std::fs::write(dir.path().join("README.md"), "").expect("write markdown");
        std::fs::create_dir_all(dir.path().join("nested")).expect("create nested");
        std::fs::write(dir.path().join("nested/mod.rs"), "").expect("write nested");

        let files = rust_source_files(dir.path())
            .into_iter()
            .map(|path| {
                path.strip_prefix(dir.path())
                    .expect("under tempdir")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();

        assert_eq!(files, vec!["lib.rs", "nested/mod.rs"]);
    }
}
