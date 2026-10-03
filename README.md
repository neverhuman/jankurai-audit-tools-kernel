# jankurai-tools-kernel

<!-- jankurai-badge:start -->
[![Jankurai score: 89/100](agent/jankurai-badge.svg)](agent/jankurai-badge.json)
<!-- jankurai-badge:end -->

Historical score from the committed [baseline report](agent/baselines/main.repo-score.json)
and [auditor metadata](agent/jankurai-badge.json).

Shared audit substrate for the **jankurai** auditor and the Jankurai standard.
This repository ships one crate, `jankurai-audit-kernel` (model, scan, rules,
caps, boundaries, validation, render), extracted from `jankurai-core` so the
core CLI and sibling tools depend on one kernel. It is one member of the Jankurai
split family; read [`SPLIT.md`](SPLIT.md) for the family contract and
[`AGENTS.md`](AGENTS.md) for agent routing rules.

## Contributor setup

This repository supplies shared inventory, findings, boundary rules and report models to
[Jankurai](https://github.com/neverhuman/jankurai). For binary installation,
your first audit, and the complete family build, start at the hub.

Install Rust **1.97.1**, a native compiler/linker and Node.js **24** for CI
control tests. Then run the crate's contributor checks:

```sh
cargo fetch --locked
cargo test --workspace --locked
bash scripts/ci-local.sh required
```

The native library does not need Node.js at runtime. The complete quality lane
also needs the pinned security tools and auditor installed by the owning CI
setup; see [testing](docs/testing.md). Local recipes are in the
[Justfile](Justfile). CI runs on the forge and our own hosts; GitHub is a
publishing mirror only and runs no workflows.

## Layout

| Path | Role |
| --- | --- |
| `crates/jankurai-audit-kernel` | shared Rust audit substrate (library) |
| `schemas/` | JSON Schemas for the auditor's artifacts |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI helpers |

## Documentation

- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Boundaries](docs/boundaries.md)
- [CI providers and CI evidence](docs/ci-providers.md)
- [Release process](docs/release.md)
- [Agent exceptions and overrides](docs/exceptions.md)

## Versioning

The current version is recorded in [`VERSION`](VERSION) and the change history in
[`CHANGELOG.md`](CHANGELOG.md). Release mechanics are documented in
[`docs/release.md`](docs/release.md).

## License

See [`LICENSE`](LICENSE).
