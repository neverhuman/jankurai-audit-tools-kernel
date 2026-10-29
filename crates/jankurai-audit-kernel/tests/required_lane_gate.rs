//! The required lane is this repository's merge gate, so it has to compile and
//! test the kernel. It once ran only `cargo metadata --no-deps`, which compiles
//! nothing: a pull request that broke the build, clippy or a test passed the
//! gate. These assertions pin the four commands the lane must run.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crate lives at <root>/crates/<crate>")
        .to_path_buf()
}

fn lane(name: &str) -> String {
    let path = repo_root().join("ops/ci").join(format!("{name}.sh"));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn required_lane_builds_lints_and_tests() {
    let script = lane("required");
    for command in [
        "cargo metadata --no-deps --format-version 1 --locked --offline",
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --locked --offline -- -D warnings",
        "cargo nextest run --workspace --locked --offline",
    ] {
        assert!(
            script.contains(command),
            "ops/ci/required.sh must run `{command}`"
        );
    }
}

#[test]
fn fast_lane_stays_the_quick_subset() {
    let script = lane("fast");
    assert!(script.contains("cargo check --workspace --locked"));
    assert!(script.contains("cargo nextest run --workspace --locked"));
    assert!(
        !script.contains("cargo clippy"),
        "clippy belongs to the required lane; fast stays the quick subset"
    );
}

#[test]
fn ci_local_routes_required_to_the_lane_script() {
    let output = std::process::Command::new("bash")
        .args(["scripts/ci-local.sh", "--which", "required"])
        .current_dir(repo_root())
        .output()
        .expect("probe the CI dispatcher's required lane");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "ops/ci/required.sh"
    );
}

#[test]
fn hosted_required_recipe_is_unique_and_routes_through_ci_local() {
    let output = std::process::Command::new("just")
        .args(["--show", "required"])
        .current_dir(repo_root())
        .output()
        .expect("resolve the hosted required recipe");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("bash scripts/ci-local.sh required"));
}
