//! Runs the real binary against the real npm-generated SBOMs in testdata/
//! (see testdata/regenerate-npm-fixtures.sh), checking what a CI job
//! actually consumes: the exit code and the machine-readable output.

use serde_json::Value;
use std::process::{Command, Output};

const BEFORE: &str = "testdata/npm-before.cdx.json";
const AFTER: &str = "testdata/npm-after.cdx.json";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bomdelta"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn real_npm_release_diff_reports_exactly_the_expected_changes() {
    let out = run(&["--format", "json", BEFORE, AFTER]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));

    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    let got: Vec<(String, String, String)> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["severity"].as_str().unwrap().to_string(),
                f["rule"].as_str().unwrap().to_string(),
                f["component"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    // Worked out by hand from the two lockfiles: express 4.20.0 pins older
    // cookie, finalhandler, path-to-regexp and serve-static, and nests an
    // older second copy of qs and send; tinymce 7 is GPL; zod is new.
    let expected = [
        ("high", "downgraded", "npm/cookie"),
        ("high", "downgraded", "npm/express"),
        ("high", "downgraded", "npm/finalhandler"),
        ("high", "downgraded", "npm/path-to-regexp"),
        ("high", "downgraded", "npm/serve-static"),
        ("high", "license-changed", "npm/tinymce"),
        ("medium", "older-copy-added", "npm/qs"),
        ("medium", "older-copy-added", "npm/send"),
        ("info", "upgraded", "npm/tinymce"),
        ("info", "added", "npm/zod"),
    ];
    let expected: Vec<_> = expected
        .iter()
        .map(|(s, r, c)| (s.to_string(), r.to_string(), c.to_string()))
        .collect();
    assert_eq!(got, expected);

    assert_eq!(doc["before"]["subject"], "demo-app 1.0.0");
    assert_eq!(doc["after"]["subject"], "demo-app 1.1.0");
    assert_eq!(doc["failOn"], "high");
    assert_eq!(doc["failing"], 6);
}

#[test]
fn fail_on_threshold_changes_only_the_exit_code() {
    let none = run(&["--fail-on", "none", BEFORE, AFTER]);
    assert_eq!(none.status.code(), Some(0));
    assert!(stdout(&none).contains("reporting only"));

    let medium = run(&["--fail-on=medium", "--format=json", BEFORE, AFTER]);
    assert_eq!(medium.status.code(), Some(1));
    let doc: Value = serde_json::from_str(&stdout(&medium)).unwrap();
    assert_eq!(doc["failing"], 8);
}

#[test]
fn the_same_sbom_on_both_sides_passes() {
    let out = run(&[BEFORE, BEFORE]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("No dependency changes."));
}

#[test]
fn markdown_is_a_table_a_pr_comment_can_render() {
    let out = run(&["--format", "markdown", BEFORE, AFTER]);
    let text = stdout(&out);
    assert!(text.starts_with("### bomdelta: demo-app 1.0.0 -> demo-app 1.1.0"));
    assert!(text.contains("| Severity | Change | Component | Detail |"));
    assert!(text.contains("| high | license-changed | `npm/tinymce` | MIT, permissive -> GPL-2.0-or-later, strong copyleft |"));
}

#[test]
fn spdx_input_is_a_usage_error_not_a_clean_diff() {
    let out = run(&[BEFORE, "testdata/spdx-2.3.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("SPDX"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run(&[BEFORE]).status.code(), Some(2));
    assert_eq!(
        run(&["--fail-on", "critical", BEFORE, AFTER]).status.code(),
        Some(2)
    );
    assert_eq!(run(&["--frobnicate", BEFORE, AFTER]).status.code(), Some(2));
    assert_eq!(
        run(&[BEFORE, "testdata/does-not-exist.json"]).status.code(),
        Some(2)
    );
}

#[test]
fn help_and_version_exit_0() {
    assert_eq!(run(&["--help"]).status.code(), Some(0));
    let v = run(&["--version"]);
    assert_eq!(v.status.code(), Some(0));
    assert_eq!(
        stdout(&v).trim(),
        format!("bomdelta {}", env!("CARGO_PKG_VERSION"))
    );
}
