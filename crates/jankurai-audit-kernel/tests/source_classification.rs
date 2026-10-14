use jankurai_audit_kernel::audit::{fs, helpers, scan};
use std::fs as disk;
use std::path::Path;

fn inventory(path: &str, source: &str) -> jankurai_audit_kernel::model::FileInfo {
    let root = tempfile::tempdir().unwrap();
    let full = root.path().join(path);
    disk::create_dir_all(full.parent().unwrap()).unwrap();
    disk::write(&full, source).unwrap();
    let files = fs::inventory_repo(root.path()).unwrap();
    assert_eq!(files.len(), 1);
    let from_disk = files.into_iter().next().unwrap();
    let from_overlay = fs::file_info_from_candidate(path, source.as_bytes(), 4096);
    assert_eq!(from_disk.is_generated, from_overlay.is_generated);
    assert_eq!(from_disk.is_code, from_overlay.is_code);
    assert_eq!(from_disk.text, source);
    assert_eq!(from_overlay.text, source);
    from_disk
}

#[test]
fn authored_names_do_not_become_generated_zones() {
    for path in [
        "crates/kernel/tests/generated_zone_pairs.rs",
        "src/generated_policy.rs",
        "generated_parser/src/lib.rs",
        "generatedness/a.ts",
        "src/artifacts_manager.rs",
    ] {
        let file = inventory(path, "// TODO: adversarial fixture\n");
        assert!(!file.is_generated, "{path}");
        assert!(file.is_code, "{path}");
        let ctx = context(file);
        assert!(scan::generated_zone_issues(&ctx).is_empty(), "{path}");
    }
}

#[test]
fn conventional_output_directories_keep_generated_governance_checks() {
    for path in ["generated/client.ts", "sdk/gen/a.rs", "sdk/artifacts/a.js"] {
        let file = inventory(path, "// TODO: adversarial fixture\n");
        assert!(file.is_generated, "{path}");
        let hits = scan::generated_zone_issues(&context(file));
        assert!(hits
            .iter()
            .any(|hit| hit.problem.contains("ownership rules")));
        assert!(hits.iter().any(|hit| hit.problem.contains("TODO/stub")));
    }
}

#[test]
fn javascript_and_typescript_module_variants_are_complete_code_inputs() {
    for path in [
        "vite.config.mts",
        "vite.config.cts",
        "src/a.mjs",
        "src/a.cjs",
    ] {
        let file = inventory(path, "export default { server: { host: true } };\n");
        assert!(file.is_code, "{path}");
        assert!(!file.is_generated, "{path}");
    }
}

fn context(file: jankurai_audit_kernel::model::FileInfo) -> helpers::AuditContext {
    helpers::AuditContext {
        root: "/unused".into(),
        scope_files: vec![file.clone()],
        all_files: vec![file],
        scope_paths: vec![],
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    }
}

const PRODUCT_ONLY_ENTRIES: &[&str] = &[
    "proof-routing",
    "proofbind",
    "proofmark-rust",
    "copy-code",
    "ux-qa",
    "contract-drift",
    "rust-witness",
    "vibe-coverage",
    "coverage-evidence",
    "authz-matrix",
    "release-readiness",
    "cost-budget",
];

const NEVER_DOCS_GATED_ENTRIES: &[&str] = &[
    "security",
    "ci-bad-behavior",
    "git-bad-behavior",
    "release-bad-behavior",
    "db-migration-analyze",
    "agent-tool-supply",
];

fn applicable_ids(ctx: &helpers::AuditContext) -> Vec<&'static str> {
    helpers::TOOL_ADOPTION_CATALOG
        .iter()
        .filter(|entry| (entry.applicability)(ctx))
        .map(|entry| entry.id)
        .collect()
}

/// A docs repository with a small Rust lint tool, a migrations folder and
/// agent control-plane files: no authored product surface code, but plenty
/// for security and supply-chain checks to look at.
fn docs_shaped_tree(policy: &str) -> Vec<(&'static str, String)> {
    vec![
        ("agent/audit-policy.toml", policy.to_string()),
        ("agent/vibe-coverage.toml", "schema_version = 1\n".into()),
        ("AGENTS.md", "# Agents\n".into()),
        (
            "README.md",
            "# Internal wiki\n\nRelease and rollback notes. Auth runbook. Budget quota.\n".into(),
        ),
        ("docs/runbook.md", "# Runbook\n".into()),
        (
            "Cargo.toml",
            "[package]\nname = \"wiki-link-lint\"\nversion = \"0.1.0\"\n".into(),
        ),
        (
            "tools/wiki-link-lint.rs",
            "fn main() {\n    println!(\"lint docs\");\n}\n".into(),
        ),
        (
            "migrations/0001_init.sql",
            "create table pages (id bigint primary key);\n".into(),
        ),
        (
            "Justfile",
            "required:\n    gitleaks detect --no-banner\n    cargo test\n".into(),
        ),
        (
            "scripts/publish.sh",
            "#!/usr/bin/env bash\n# release, rollback, auth token, budget quota\necho ok\n".into(),
        ),
    ]
}

#[test]
fn docs_opt_in_without_product_code_skips_only_product_entries() {
    let tree = docs_shaped_tree("minimum_score = 85\ntarget_stack = \"docs\"\n");
    let f = fixture_owned(&tree);
    let ctx = &f.ctx;

    assert!(helpers::declared_docs_target_stack(ctx));
    assert!(!helpers::has_authored_product_code(ctx));
    assert!(helpers::docs_only_repo(ctx));

    let applicable = applicable_ids(ctx);
    for id in PRODUCT_ONLY_ENTRIES {
        assert!(
            !applicable.contains(id),
            "{id} should be not applicable for an opted-in docs repo"
        );
    }
    for id in NEVER_DOCS_GATED_ENTRIES {
        assert!(
            applicable.contains(id),
            "{id} must stay applicable even for an opted-in docs repo: {applicable:?}"
        );
    }
    assert!(!helpers::security_sbom_provenance_applicable(ctx));
    assert!(!helpers::security_in_ci_audit_applicable(ctx));

    let tool_dim = helpers::docs_only_not_applicable_dimension(
        ctx,
        "Jankurai tool adoption and CI replacement",
    )
    .expect("tool adoption should be neutral for docs-only repos");
    assert_eq!(tool_dim.score, helpers::DOCS_ONLY_NEUTRAL_SCORE);
    assert!(tool_dim
        .evidence
        .iter()
        .any(|line| line.contains("not_applicable")));

    let obs_dim =
        helpers::docs_only_not_applicable_dimension(ctx, "Observability and repair evidence")
            .expect("observability should be neutral for docs-only repos");
    assert_eq!(obs_dim.score, helpers::DOCS_ONLY_NEUTRAL_SCORE);
}

#[test]
fn code_repo_without_docs_opt_in_keeps_every_check() {
    // Same tree shape (code only under tools/ and migrations/, outside the
    // product surface) but no `target_stack = "docs"` opt-in: nothing may be
    // switched off.
    for policy in [
        "minimum_score = 85\n".to_string(),
        "minimum_score = 85\ntarget_stack = \"rust-ts-vite-react-postgres-bounded-python\"\n"
            .to_string(),
        "minimum_score = = broken\ntarget_stack = \"docs\"\n".to_string(),
    ] {
        let tree = docs_shaped_tree(&policy);
        let f = fixture_owned(&tree);
        let ctx = &f.ctx;

        assert!(!helpers::has_authored_product_code(ctx));
        assert!(!helpers::docs_only_repo(ctx), "policy: {policy}");

        let applicable = applicable_ids(ctx);
        for id in NEVER_DOCS_GATED_ENTRIES.iter().chain(
            [
                "vibe-coverage",
                "authz-matrix",
                "release-readiness",
                "cost-budget",
            ]
            .iter(),
        ) {
            assert!(
                applicable.contains(id),
                "{id} must stay applicable without the docs opt-in ({policy}): {applicable:?}"
            );
        }
        assert!(helpers::security_sbom_provenance_applicable(ctx));
        assert!(helpers::security_in_ci_audit_applicable(ctx));
        for name in [
            "Jankurai tool adoption and CI replacement",
            "Observability and repair evidence",
        ] {
            assert!(helpers::docs_only_not_applicable_dimension(ctx, name).is_none());
        }
    }
}

#[test]
fn product_code_restores_product_only_dimension_applicability() {
    let f = fixture(&[
        (
            "agent/audit-policy.toml",
            "minimum_score = 85\ntarget_stack = \"docs\"\n",
        ),
        ("AGENTS.md", "# Agents\n"),
        ("README.md", "# Product crate\n"),
        (
            "Cargo.toml",
            "[package]\nname = \"widget-ledger\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn balance() -> i64 {\n    0\n}\n"),
    ]);
    let ctx = &f.ctx;

    // The declaration is present, but product code overrides it.
    assert!(helpers::declared_docs_target_stack(ctx));
    assert!(helpers::has_authored_product_code(ctx));
    assert!(!helpers::docs_only_repo(ctx));
    assert!(helpers::security_sbom_provenance_applicable(ctx));
    assert!(helpers::security_in_ci_audit_applicable(ctx));
    assert!(applicable_ids(ctx).contains(&"copy-code"));
    assert!(helpers::docs_only_not_applicable_dimension(
        ctx,
        "Jankurai tool adoption and CI replacement",
    )
    .is_none());
}

fn fixture_owned(files: &[(&'static str, String)]) -> Fixture {
    let borrowed = files
        .iter()
        .map(|(path, contents)| (*path, contents.as_str()))
        .collect::<Vec<_>>();
    fixture(&borrowed)
}

struct Fixture {
    _root: tempfile::TempDir,
    ctx: helpers::AuditContext,
}

fn fixture(files: &[(&str, &str)]) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    for (path, contents) in files {
        write(root.path(), path, contents);
    }
    let all_files = fs::inventory_repo(root.path()).unwrap();
    let ctx = helpers::AuditContext {
        root: root.path().to_path_buf(),
        scope_files: all_files.clone(),
        scope_paths: vec![],
        all_files,
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    };
    Fixture { _root: root, ctx }
}

fn write(root: &Path, path: &str, contents: &str) {
    let full = root.join(path);
    disk::create_dir_all(full.parent().unwrap()).unwrap();
    disk::write(full, contents).unwrap();
}
