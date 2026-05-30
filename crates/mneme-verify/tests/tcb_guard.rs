//! TCB guard: production source must not contain forbidden patterns (§10).

use std::fs;
use std::path::PathBuf;

const FORBIDDEN: &[(&str, &str)] = &[
    (r"\.unwrap\(", "unwrap"),
    (r"\.expect\(", "expect"),
    (r"\bpanic!\(", "panic!"),
    (r"\bunreachable!\(", "unreachable!"),
    (r"\btodo!\(", "todo!"),
    (r"\bunimplemented!\(", "unimplemented!"),
    (r"\banyhow::", "anyhow"),
    (r"\bunsafe\b", "unsafe"),
];

#[test]
fn tcb_guard_no_forbidden_patterns() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&src).expect("read src") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            scan_file(&path, &mut violations);
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden TCB patterns:\n{}",
        violations.join("\n")
    );
}

#[test]
fn tcb_guard_no_integer_as_casts() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    for entry in fs::read_dir(&src).expect("read src") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("read");
            for (line_no, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("forbid(unsafe_code)") {
                    continue;
                }
                if line.contains(" as u") || line.contains(" as i") {
                    hits.push(format!("{}:{}: {}", path.display(), line_no + 1, trimmed));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "integer `as` casts in TCB:\n{}",
        hits.join("\n")
    );
}

fn scan_file(path: &std::path::Path, violations: &mut Vec<String>) {
    let text = fs::read_to_string(path).expect("read");
    for (pattern, name) in FORBIDDEN {
        if let Ok(re) = regex_lite(pattern) {
            for (line_no, line) in text.lines().enumerate() {
                if re.is_match(line) {
                    violations.push(format!(
                        "{}:{}: {} ({})",
                        path.display(),
                        line_no + 1,
                        line.trim(),
                        name
                    ));
                }
            }
        }
    }
}

fn regex_lite(pattern: &str) -> Result<SimpleRegex, ()> {
    Ok(SimpleRegex {
        pattern: pattern.to_string(),
    })
}

struct SimpleRegex {
    pattern: String,
}

impl SimpleRegex {
    fn is_match(&self, line: &str) -> bool {
        // Lightweight substring checks for the fixed patterns above.
        match self.pattern.as_str() {
            r"\.unwrap\(" => line.contains(".unwrap("),
            r"\.expect\(" => line.contains(".expect("),
            r"\bpanic!\(" => line.contains("panic!("),
            r"\bunreachable!\(" => line.contains("unreachable!("),
            r"\btodo!\(" => line.contains("todo!("),
            r"\bunimplemented!\(" => line.contains("unimplemented!("),
            r"\banyhow::" => line.contains("anyhow::"),
            r"\bunsafe\b" => {
                line.contains("unsafe")
                    && !line.contains("forbid(unsafe_code)")
                    && !line.contains("unsafe_code")
            }
            _ => false,
        }
    }
}
