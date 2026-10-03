# ops/ Agent Instructions

This cell owns the pinned CI lane scripts and Git hook entrypoints for
jankurai-tools-kernel.

- `ops/ci/<lane>.sh` are the canonical lane scripts. The Justfile and the
  forge-hosted CI both delegate here so local and CI runs stay identical.
  GitHub is a publishing mirror only; do not add GitHub Actions workflows.
- `ops/ci/lib.sh` holds the shared tool-version pins and artifact assertions.
- `ops/git-hooks/pre-push` runs `bash ops/ci/quality-gates.sh`. Wire it once with
  `git config core.hooksPath ops/git-hooks`.
- Proof lane: the security lane (`bash scripts/ci-local.sh security`). Run it
  before changing anything under `ops/`.
- Owner: ops.
