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

const DOCS_EXEMPT: &[&str] = &["coverage-evidence", "rust-witness", "proofmark-rust"];

fn entry(id: &str) -> &'static helpers::ToolAdoptionCatalogEntry {
    helpers::TOOL_ADOPTION_CATALOG
        .iter()
        .find(|entry| entry.id == id)
        .unwrap_or_else(|| panic!("catalog entry {id}"))
}

/// A docs repository with a small Rust lint tool, SQL migrations, a publish
/// script, agent control-plane files and coverage sources: no authored product
/// surface code, but plenty for security and release checks to look at.
fn docs_shaped_tree(policy: &str) -> Vec<(&'static str, String)> {
    vec![
        ("agent/audit-policy.toml", policy.to_string()),
        ("agent/vibe-coverage.toml", "schema_version = 1\n".into()),
        ("agent/coverage-sources.toml", "schema_version = 1\n".into()),
        ("agent/generated-zones.toml", "# none\n".into()),
        ("AGENTS.md", "# Agents\n".into()),
        ("README.md", "# Internal wiki\n".into()),
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
            "#!/usr/bin/env bash\n# release, rollback, auth token, owner_id, budget quota\necho ok\n"
                .into(),
        ),
    ]
}

#[test]
fn docs_only_exemptions_never_touch_security_or_release_integrity() {
    for (id, why) in helpers::DOCS_ONLY_EXEMPT_TOOL_IDS {
        let category = entry(id).category;
        assert!(
            !matches!(category, "security" | "release" | "git" | "ci" | "db"),
            "{id} ({category}) must not be docs-exempt"
        );
        assert!(!why.is_empty(), "{id} needs a justification");
    }
    let ids: Vec<&str> = helpers::DOCS_ONLY_EXEMPT_TOOL_IDS
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ids, DOCS_EXEMPT);
}

#[test]
fn docs_opt_in_exempts_only_product_measuring_entries_and_says_why() {
    let tree = docs_shaped_tree("minimum_score = 85\ntarget_stack = \"docs\"\n");
    let f = fixture_owned(&tree);
    let ctx = &f.ctx;

    assert!(helpers::declared_docs_target_stack(ctx));
    assert!(!helpers::has_authored_product_code(ctx));
    assert!(helpers::docs_only_repo(ctx));

    for catalog_entry in helpers::TOOL_ADOPTION_CATALOG {
        let got = helpers::tool_adoption_applicability(catalog_entry, ctx);
        if DOCS_EXEMPT.contains(&catalog_entry.id) {
            assert_eq!(
                got,
                helpers::ToolApplicability {
                    applicable: false,
                    not_applicable_reason: Some(
                        "not applicable: docs-only (target_stack=docs, no authored product code)"
                    ),
                },
                "{}",
                catalog_entry.id
            );
        } else {
            // Every other entry, security and release integrity included, is
            // exactly its own predicate: never docs-gated, never silent.
            assert_eq!(
                got,
                helpers::ToolApplicability {
                    applicable: (catalog_entry.applicability)(ctx),
                    not_applicable_reason: None,
                },
                "{}",
                catalog_entry.id
            );
        }
    }
    for id in [
        "security",
        "ci-bad-behavior",
        "git-bad-behavior",
        "release-bad-behavior",
        "release-readiness",
        "authz-matrix",
        "db-migration-analyze",
        "agent-tool-supply",
        "contract-drift",
        "vibe-coverage",
        "cost-budget",
    ] {
        assert!(
            helpers::tool_adoption_applicability(entry(id), ctx).applicable,
            "{id} must stay applicable for an opted-in docs repo"
        );
    }
    // The exemption is visible: coverage-evidence would otherwise apply here.
    assert!((entry("coverage-evidence").applicability)(ctx));
}

#[test]
fn code_repo_without_docs_opt_in_keeps_every_check() {
    for policy in [
        "minimum_score = 85\n",
        "minimum_score = 85\ntarget_stack = \"rust-ts-vite-react-postgres-bounded-python\"\n",
        "minimum_score = = broken\ntarget_stack = \"docs\"\n",
        // Schema-invalid (minimum_score out of range): never trusted.
        "minimum_score = 500\ntarget_stack = \"docs\"\n",
    ] {
        let tree = docs_shaped_tree(policy);
        let f = fixture_owned(&tree);
        let ctx = &f.ctx;

        assert!(!helpers::has_authored_product_code(ctx));
        assert!(!helpers::docs_only_repo(ctx), "policy: {policy}");
        for catalog_entry in helpers::TOOL_ADOPTION_CATALOG {
            let got = helpers::tool_adoption_applicability(catalog_entry, ctx);
            assert_eq!(got.not_applicable_reason, None, "{}", catalog_entry.id);
            assert_eq!(
                got.applicable,
                (catalog_entry.applicability)(ctx),
                "{} ({policy})",
                catalog_entry.id
            );
        }
        assert!(helpers::tool_adoption_applicability(entry("coverage-evidence"), ctx).applicable);
    }
}

#[test]
fn product_code_overrides_the_docs_declaration() {
    let f = fixture(&[
        (
            "agent/audit-policy.toml",
            "minimum_score = 85\ntarget_stack = \"docs\"\n",
        ),
        ("agent/coverage-sources.toml", "schema_version = 1\n"),
        ("AGENTS.md", "# Agents\n"),
        ("README.md", "# Product crate\n"),
        (
            "Cargo.toml",
            "[package]\nname = \"widget-ledger\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn balance() -> i64 {\n    0\n}\n"),
    ]);
    let ctx = &f.ctx;

    assert!(helpers::declared_docs_target_stack(ctx));
    assert!(helpers::has_authored_product_code(ctx));
    assert!(!helpers::docs_only_repo(ctx));
    for id in DOCS_EXEMPT {
        let got = helpers::tool_adoption_applicability(entry(id), ctx);
        assert_eq!(got.not_applicable_reason, None);
        assert_eq!(got.applicable, (entry(id).applicability)(ctx));
    }
    assert!(helpers::tool_adoption_applicability(entry("coverage-evidence"), ctx).applicable);
}

#[test]
fn declared_target_stack_reads_the_full_policy_even_past_the_text_cap() {
    // Pad the policy past a tiny capture cap: the inventory only holds a
    // truncated sample, but the declaration must still be read from the file.
    let padding = "# padding\n".repeat(64);
    let policy = format!(
        "minimum_score = 85\n{padding}target_stack = \"docs\"\n\n[scan]\ntext_capture_chars = 16\n"
    );
    let f = fixture(&[
        ("agent/audit-policy.toml", policy.as_str()),
        ("README.md", "# Docs\n"),
    ]);
    assert!(f
        .ctx
        .all_files
        .iter()
        .filter(|file| file.rel_path == "agent/audit-policy.toml")
        .all(|file| !file.text.contains("target_stack")));
    assert_eq!(
        helpers::declared_target_stack(&f.ctx).as_deref(),
        Some("docs")
    );
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
