//! The neutrality invariant that proves this crate is engine-agnostic: its
//! source must not name any Cedar (or other policy-engine) type.
//!
//! This is the grep-gate from the pluggable-policy design encoded as a test, so
//! a future edit that reaches for a `cedar_policy` / `cedar_oci` /
//! `cedar_local_agent` type inside the neutral core fails CI rather than
//! silently re-coupling the seam. Engine-specific code belongs in an adapter
//! crate (e.g. `datafusion-cedar`), never here.
//!
//! Doc comments legitimately *mention* Cedar as an example engine, so the check
//! scans only non-doc-comment lines.

use std::fs;
use std::path::Path;

/// Substrings that would indicate an engine type leaked into the neutral core.
const FORBIDDEN: &[&str] = &["cedar_policy", "cedar_oci", "cedar_local_agent"];

fn scan_dir(dir: &Path, violations: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan_dir(&path, violations);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let contents = fs::read_to_string(&path).expect("read source file");
        for (i, line) in contents.lines().enumerate() {
            let trimmed = line.trim_start();
            // Skip doc comments / line comments: prose may reference Cedar as an
            // example engine. We only care about actual code references.
            if trimmed.starts_with("//") {
                continue;
            }
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    violations.push(format!(
                        "{}:{}: forbidden engine reference `{needle}`: {}",
                        path.display(),
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
}

#[test]
fn neutral_core_names_no_engine_type() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    scan_dir(&src, &mut violations);
    assert!(
        violations.is_empty(),
        "datafusion-policy must stay engine-neutral; found:\n{}",
        violations.join("\n")
    );
}
