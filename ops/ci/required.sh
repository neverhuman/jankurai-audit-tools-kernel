#!/usr/bin/env bash
# Required lane: the merge gate that must pass on every push.
# It builds and tests the kernel, because a gate that only resolves the
# manifest compiles nothing and lets a broken build, lint or test merge.
# Runs offline against the locked graph, so `cargo fetch --locked` is the
# only setup step (see README).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "required lane: auditor identity tests"
bash ops/ci/auditor-test.sh

log "required lane: ci-local lane contract"
bash scripts/ci-local-lanes-test.sh

log "required lane: metadata + fmt + clippy + nextest"
cargo metadata --no-deps --format-version 1 --locked --offline >/dev/null
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo nextest run --workspace --locked --offline
