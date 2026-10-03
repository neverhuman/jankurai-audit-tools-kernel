#!/usr/bin/env bash
# Tool-adoption evidence lane.
#
# jankurai replaces a fleet of ad-hoc tools (manual scoring, gitleaks-only
# security, hand-rolled coverage/contract drift checks) with first-class
# subcommands. This lane runs each adopted command in CI and writes its
# evidence artifact under target/jankurai/ so the audit can prove the
# replacement actually executed. The CI host keeps the matching artifacts.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

mkdir -p target/jankurai target/jankurai/security target/jankurai/coverage \
         target/jankurai/proofbind target/jankurai/proofmark

# audit-ci / proof-routing adopt the ratchet audit command. The repair queue is
# the proof-routing evidence that changed-surface obligations were emitted.
log "tool-adoption: ratchet audit"
jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md --repair-queue-jsonl target/jankurai/repair-queue.jsonl --full

# proofbind: changed-surface proof obligation routing.
log "tool-adoption: proofbind verify"
jankurai proofbind verify . --changed-from origin/main

# proofmark-rust: in-diff mutation and coverage witness for Rust.
log "tool-adoption: proofmark rust"
jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json

# copy-code: duplication triage replacing ad-hoc copy-code review.
log "tool-adoption: copy-code"
jankurai copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md

# security: secret + dependency + SBOM/provenance evidence in one lane.
log "tool-adoption: security run"
jankurai security run . --out target/jankurai/security/evidence.json --script ops/ci/security-scans.sh

# Language adversarial checks are produced from the pinned auditor source in
# github-setup.sh. Keep a workspace test log as local crate evidence.
log "tool-adoption: kernel crate tests"
cargo test --workspace --locked 2>&1 | tee -a target/jankurai/language-bad-behavior.log

# vibe-coverage needs the tips tree; skip until this crate vendors those docs.
if [[ -d tips/vibe_coding ]]; then
  log "tool-adoption: vibe coverage"
  jankurai vibe coverage --source agent/vibe-coverage.toml --tips tips/vibe_coding --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md
fi

# coverage-evidence: coverage audit replacing line-only coverage gates.
if [[ -f agent/coverage-sources.toml ]]; then
  log "tool-adoption: coverage audit"
  jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
fi
