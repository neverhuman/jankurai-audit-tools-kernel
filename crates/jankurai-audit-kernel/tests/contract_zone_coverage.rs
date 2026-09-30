//! HLT-007 fixture coverage: a contract file is covered by a contract-first zone (its
//! `source`) or by a code-first zone (its `path` with `write_policy = "generated_output"`
//! plus a drift check that runs the regenerate command).

use jankurai_audit_kernel::audit::{fs, helpers, scan};
use std::fs as disk;

fn context(root: &std::path::Path, files: &[(&str, &str)]) -> helpers::AuditContext {
    for (path, body) in files {
        let full = root.join(path);
        disk::create_dir_all(full.parent().unwrap()).unwrap();
        disk::write(&full, body).unwrap();
    }
    let all_files = fs::inventory_repo(root).unwrap();
    helpers::AuditContext {
        root: root.to_path_buf(),
        scope_files: all_files.clone(),
        all_files,
        scope_paths: vec![],
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    }
}

const SCHEMA: &str = "{\n  \"title\": \"widget envelope\"\n}\n";
const DRIFT_TEST: &str = r#"#[test]
fn schema_is_not_stale() {
    // regenerates with `just contracts` and compares the checked-in file
    assert!(std::process::Command::new("just").arg("contracts").status().is_ok());
}
"#;

#[test]
fn code_first_zone_covers_its_generated_contract() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[
            ("contracts/widget-envelope.schema.json", SCHEMA),
            (
                "agent/generated-zones.toml",
                r#"[[zone]]
path = "contracts/widget-envelope.schema.json"
source = "crates/widget-types"
command = "just contracts"
read_only = true
write_policy = "generated_output"
"#,
            ),
            ("crates/widget-types/tests/contract_drift.rs", DRIFT_TEST),
        ],
    );
    assert!(
        scan::contract_source_hits(&ctx).is_empty(),
        "code-first contract with a drift test must not be flagged"
    );
}

#[test]
fn code_first_zone_may_name_the_contract_directory() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[
            ("contracts/widget-envelope.schema.json", SCHEMA),
            (
                "agent/generated-zones.toml",
                r#"[[zone]]
path = "contracts"
source = "crates/widget-types"
command = "just contracts"
read_only = true
write_policy = "generated_output"
"#,
            ),
            ("tests/contract_drift.rs", DRIFT_TEST),
        ],
    );
    assert!(scan::contract_source_hits(&ctx).is_empty());
}

#[test]
fn contract_first_zone_still_covers_its_source() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[
            ("contracts/widget-api.yaml", "openapi: 3.1.0\n"),
            (
                "agent/generated-zones.toml",
                r#"[[zone]]
path = "sdk/gen"
source = "contracts/widget-api.yaml"
command = "just sdk"
read_only = true
write_policy = "generated_output"
"#,
            ),
        ],
    );
    assert!(scan::contract_source_hits(&ctx).is_empty());
}

#[test]
fn contract_without_any_zone_is_still_flagged() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[("contracts/widget-envelope.schema.json", SCHEMA)],
    );
    let hits = scan::contract_source_hits(&ctx);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].problem.contains("no generated zone entry"));
}

#[test]
fn zone_path_pointing_elsewhere_does_not_cover_the_contract() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[
            ("contracts/widget-envelope.schema.json", SCHEMA),
            (
                "agent/generated-zones.toml",
                r#"[[zone]]
path = "sdk/gen/client.ts"
source = "crates/widget-types"
command = "just sdk"
read_only = true
write_policy = "generated_output"
"#,
            ),
            ("tests/contract_drift.rs", DRIFT_TEST),
        ],
    );
    let hits = scan::contract_source_hits(&ctx);
    assert_eq!(hits.len(), 1, "unrelated zone path must not grant coverage");
}

#[test]
fn generated_output_without_a_drift_check_is_still_flagged() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(
        root.path(),
        &[
            ("contracts/widget-envelope.schema.json", SCHEMA),
            (
                "agent/generated-zones.toml",
                r#"[[zone]]
path = "contracts/widget-envelope.schema.json"
source = "crates/widget-types"
command = "just contracts"
read_only = true
write_policy = "generated_output"
"#,
            ),
        ],
    );
    let hits = scan::contract_source_hits(&ctx);
    assert_eq!(
        hits.len(),
        1,
        "a generated contract with no drift check stays handwritten in practice"
    );
}
