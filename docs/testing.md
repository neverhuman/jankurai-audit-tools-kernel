# jankurai-tools-kernel Testing

Testing is routed proof. Agents should not guess which tests matter; route
through `agent/test-map.json` to the smallest lane that proves the change.

| Lane | Purpose |
| --- | --- |
| `required` | merge gate: lock resolves, then fmt, clippy and the test suite |
| `fast` | quick subset of `required` for most edits (`cargo check` + tests) |
| `security` | secret scanning and dependency vulnerability scanning |
| `audit` | jankurai repo score and hard-rule findings |
| `gates` | aggregate gate: required, fast, security, and audit |

## Required lane

The required lane is the merge gate. It must fail when the kernel stops
building, linting or testing, so it runs the full set:

```bash
just required
bash scripts/ci-local.sh required
```

Both invoke `ops/ci/required.sh`, which runs `cargo metadata --no-deps
--locked --offline`, `cargo fmt --all --check`, `cargo clippy --workspace
--all-targets --locked --offline -- -D warnings` and `cargo nextest run
--workspace --locked --offline`. Every command is offline against the locked
graph, so `cargo fetch --locked` (see `just setup`) is the only setup step.

## Fast lane

The fast lane is the narrowest proof loop for agent iteration:

```bash
just fast            # cargo check --workspace --locked + cargo nextest run --workspace
bash scripts/ci-local.sh fast
```

Both invoke `ops/ci/fast.sh`, the exact script forge-hosted CI runs, so local
runs never drift from CI.

## Rust property and integration tests

The kernel crate carries unit tests inline in `crates/jankurai-audit-kernel/src`
and integration/property tests under `crates/jankurai-audit-kernel/tests`. New
detector or rule behavior should land with a focused test that exercises the
matcher against a fixture string so the detector stays deterministic. Run them
with:

```bash
cargo test --workspace --locked
```

## Security lane

```bash
just security        # gitleaks detect ... + cargo audit
bash scripts/ci-local.sh security
```

`gitleaks` scans for committed secrets and `cargo audit` checks the Rust
dependency tree against the advisory database. Both run in CI via
`ops/ci/security.sh`.

## Audit lane

```bash
just audit           # jankurai audit . --json .jankurai/repo-score.json --md .jankurai/repo-score.md
bash scripts/ci-local.sh audit
```

The audit lane writes `repo-score` artifacts that CI uploads. The score gate is
configured in `agent/audit-policy.toml` (`minimum_score = 85`,
`fail_on = ["critical", "high"]`).

## Detection-pattern source and false positives

The kernel modules under `crates/jankurai-audit-kernel/src/audit` are detector
definitions. They contain the literal marker strings the auditor searches for.
When the auditor scans this repo, those markers can look like product-code
hazards even though they are pattern data. The policy in
`agent/audit-policy.toml` (`[dead_language] allow_terms`) and the boundary and
exception manifests under `agent/` keep the detector source from being misread.
See `docs/boundaries.md` and `docs/exceptions.md`.

## Repair receipts and telemetry

When a proof lane fails, keep the next agent on the shortest rerun path. Record
the failing command, exit code, changed paths, artifact paths, and rerun command
in the receipt, and prefer structured JSON envelopes under `target/jankurai/`
over ad hoc log spam.
