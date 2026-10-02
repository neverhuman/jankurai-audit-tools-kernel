//! Fixture repositories for the CI-provider abstraction.
//!
//! The audit used to recognise only `.github/workflows/`, so a repository gated
//! by a forge that never executes committed workflow files earned no CI credit
//! and was told to add a workflow the forge would ignore. These fixtures pin the
//! four cases: a forge declaration backed by a real lane, the same declaration
//! pointing at a lane that runs nothing, a GitHub Actions repository, and a
//! repository with no CI at all.

use jankurai_audit_kernel::audit::{ci_provider, finding_builder, fs, helpers, scan};
use std::fs as disk;
use std::path::Path;

struct Fixture {
    _root: tempfile::TempDir,
    ctx: helpers::AuditContext,
}

/// Build a repository on disk from `(path, contents)` pairs and inventory it the
/// way an audit run does.
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

/// Minimal Rust product surface, so the repository is high-risk and the CI caps
/// are in scope at all.
const PRODUCT: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[package]\nname = \"widgetworks-ledger\"\nversion = \"0.1.0\"\n",
    ),
    ("src/lib.rs", "pub fn balance() -> i64 {\n    0\n}\n"),
];

const DECLARATION: &str = "\
schema_version = \"2\"
provider = \"jeryu\"

[[lane]]
name = \"required\"
command = \"just required\"
runs = [\"jankurai audit\", \"cargo audit\", \"gitleaks\"]
";

/// The lane the forge runs: a one-line recipe that delegates to a script, which
/// is where the real commands live.
const THIN_JUSTFILE: &str = "required:\n    bash scripts/gate.sh\n";

const FULL_GATE: &str = "\
#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo audit
gitleaks detect --no-banner
jankurai audit . --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md
";

/// A lane that exists but proves nothing: the declaration above claims three
/// tools it never runs.
const EMPTY_GATE: &str = "#!/usr/bin/env bash\nset -euo pipefail\ncargo test --workspace\n";

const WORKFLOW: &str = "\
name: ci
on:
  push:
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit
      - run: gitleaks detect --no-banner
      - run: jankurai audit . --json target/jankurai/repo-score.json
";

/// A fixture repository: the product surface plus the CI surface under test.
fn build(extra: &[(&str, &str)]) -> Fixture {
    let pairs: Vec<(&str, &str)> = PRODUCT
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .collect();
    fixture(&pairs)
}

// (a) A forge declaration whose lane really runs the tools earns the credit.
#[test]
fn forge_declaration_backed_by_a_real_lane_earns_ci_credit() {
    let f = build(&[
        (".jeryu/ci.toml", DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", FULL_GATE),
    ]);
    let ctx = &f.ctx;

    let surface = ci_provider::detect(&ctx.all_files);
    assert!(surface.has(ci_provider::CiProvider::Jeryu));
    assert!(!surface.has(ci_provider::CiProvider::GithubActions));
    assert_eq!(
        surface.lanes[0].verified_tools,
        vec!["jankurai audit", "cargo audit", "gitleaks"]
    );
    assert!(surface.lanes[0].unverified_tools.is_empty());

    assert!(helpers::is_high_risk_repo(ctx));
    assert!(
        helpers::has_jankurai_audit_ci_lane(ctx),
        "the declared lane runs the audit"
    );
    assert!(
        helpers::has_secret_or_dependency_scans(ctx),
        "the declared lane runs secret and dependency scans"
    );
    assert!(
        helpers::tool_adoption_ci_text(ctx).contains("jankurai audit"),
        "tool adoption sees the lane's CI command evidence"
    );

    // The repair route points at the declaration, never at a workflow file the
    // forge would not execute.
    assert_eq!(
        ci_provider::audit_lane_anchor_path(&ctx.all_files),
        ".jeryu/ci.toml"
    );
    let fix = ci_provider::audit_lane_fix(&ctx.all_files);
    assert!(fix.contains(".jeryu/ci.toml") && !fix.contains(".github/workflows"));
    assert!(!fix.contains("agent/ci.toml"));
    let (_, path, _, _) =
        finding_builder::dimension_soft_route_for(ctx, "Security and supply-chain posture");
    assert_eq!(path, ".jeryu/ci.toml");
    assert_eq!(
        finding_builder::evidence_kind_for_path(".jeryu/ci.toml"),
        "workflow-command"
    );
}

// (b) The same declaration pointing at a lane that runs none of it earns nothing.
#[test]
fn forge_declaration_without_a_real_lane_earns_nothing() {
    let f = build(&[
        (".jeryu/ci.toml", DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", EMPTY_GATE),
    ]);
    let ctx = &f.ctx;

    let surface = ci_provider::detect(&ctx.all_files);
    assert!(surface.has(ci_provider::CiProvider::Jeryu));
    assert!(surface.lanes[0].verified_tools.is_empty());
    assert_eq!(
        surface.lanes[0].unverified_tools,
        vec!["jankurai audit", "cargo audit", "gitleaks"]
    );

    assert!(!helpers::has_jankurai_audit_ci_lane(ctx));
    assert!(!helpers::has_secret_or_dependency_scans(ctx));
    assert!(!helpers::tool_adoption_ci_text(ctx).contains("jankurai audit"));
}

// A declaration naming a lane that does not exist is not a provider at all.
#[test]
fn forge_declaration_naming_a_missing_lane_earns_nothing() {
    let f = build(&[
        (".jeryu/ci.toml", DECLARATION),
        ("Justfile", "fast:\n    cargo check\n"),
    ]);
    let ctx = &f.ctx;

    let surface = ci_provider::detect(&ctx.all_files);
    assert!(!surface.has(ci_provider::CiProvider::Jeryu));
    assert_eq!(surface.unresolved_lanes, vec!["required"]);
    assert!(!helpers::has_jankurai_audit_ci_lane(ctx));
    assert!(!helpers::has_secret_or_dependency_scans(ctx));
}

// (c) A GitHub Actions repository behaves exactly as before.
#[test]
fn github_workflow_repository_is_unchanged() {
    let f = build(&[(".github/workflows/ci.yml", WORKFLOW)]);
    let ctx = &f.ctx;

    let surface = ci_provider::detect(&ctx.all_files);
    assert!(surface.has(ci_provider::CiProvider::GithubActions));
    assert!(!surface.has(ci_provider::CiProvider::Jeryu));

    assert!(helpers::has_jankurai_audit_ci_lane(ctx));
    assert!(helpers::has_secret_or_dependency_scans(ctx));
    assert!(helpers::tool_adoption_ci_text(ctx).contains("jankurai audit"));
    assert_eq!(
        ci_provider::audit_lane_anchor_path(&ctx.all_files),
        ".github/workflows/jankurai.yml"
    );
    let (_, path, _, _) =
        finding_builder::dimension_soft_route_for(ctx, "Security and supply-chain posture");
    assert_eq!(path, ".github/workflows/jankurai.yml");
}

// (d) A repository with no CI at all still gets the caps.
#[test]
fn repository_without_ci_still_gets_the_caps() {
    let f = build(&[]);
    let ctx = &f.ctx;

    assert!(ci_provider::detect(&ctx.all_files).providers.is_empty());
    assert!(helpers::is_high_risk_repo(ctx));
    assert!(!helpers::has_jankurai_audit_ci_lane(ctx));
    assert!(!helpers::has_secret_or_dependency_scans(ctx));
    assert_eq!(
        ci_provider::audit_lane_anchor_path(&ctx.all_files),
        ".github/workflows/jankurai.yml",
        "with no provider the route keeps the GitHub Actions default"
    );
}

// The forge's workflow-shaped hardening rules stay bound to GitHub Actions: a
// declaration is not YAML and must not attract workflow-key findings.
#[test]
fn forge_declaration_does_not_attract_github_workflow_findings() {
    let f = build(&[
        (".jeryu/ci.toml", DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", FULL_GATE),
    ]);
    let hits = scan::ci_hardening_hits(&f.ctx);
    assert!(hits.is_empty(), "{hits:?}");
}

/// The `.jeryu/ci.toml` older repositories already carry: schema version 1, a
/// provider-policy flag, no `provider` and no lanes.
const SCHEMA_V1_DECLARATION: &str = "schema_version = \"1\"\ngithub_actions_required = true\n";

// A schema-1 `.jeryu/ci.toml` parses without error, is not jeryu evidence, and
// draws no finding of its own; the repository scores as if it had no CI.
#[test]
fn schema_v1_jeryu_file_is_not_evidence_and_draws_no_finding() {
    let f = build(&[
        (".jeryu/ci.toml", SCHEMA_V1_DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", FULL_GATE),
    ]);
    let ctx = &f.ctx;

    let surface = ci_provider::detect(&ctx.all_files);
    assert!(surface.providers.is_empty());
    assert!(surface.lanes.is_empty());
    assert!(surface.unresolved_lanes.is_empty());
    assert!(!helpers::has_jankurai_audit_ci_lane(ctx));
    assert!(!helpers::has_secret_or_dependency_scans(ctx));
    assert_eq!(
        ci_provider::audit_lane_anchor_path(&ctx.all_files),
        ".github/workflows/jankurai.yml"
    );
    let hits = scan::ci_hardening_hits(ctx);
    assert!(hits.is_empty(), "{hits:?}");
}

// The old `agent/ci.toml` location is no longer read, even with a valid
// schema-2 declaration in it.
#[test]
fn declaration_in_the_agent_folder_is_ignored() {
    let f = build(&[
        ("agent/ci.toml", DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", FULL_GATE),
    ]);
    let ctx = &f.ctx;
    assert!(!ci_provider::detect(&ctx.all_files).has(ci_provider::CiProvider::Jeryu));
    assert!(!helpers::has_jankurai_audit_ci_lane(ctx));
}

// CI-cap findings (no audit lane, no security lane, no scans) point at the
// surface that gates the repository.
#[test]
fn ci_findings_path_follows_the_provider() {
    let forge = build(&[
        (".jeryu/ci.toml", DECLARATION),
        ("Justfile", THIN_JUSTFILE),
        ("scripts/gate.sh", EMPTY_GATE),
    ]);
    assert_eq!(
        ci_provider::ci_findings_path(&forge.ctx.all_files),
        ".jeryu/ci.toml"
    );
    let github = build(&[(".github/workflows/ci.yml", WORKFLOW)]);
    assert_eq!(
        ci_provider::ci_findings_path(&github.ctx.all_files),
        ".github/workflows"
    );
    let none = build(&[]);
    assert_eq!(
        ci_provider::ci_findings_path(&none.ctx.all_files),
        ".github/workflows"
    );
}
