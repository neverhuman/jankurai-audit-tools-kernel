# Changelog

All notable changes to jankurai-tools-kernel are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The authoritative
version string lives in [`VERSION`](VERSION).

## [Unreleased]

### Changed

- `HLT-007-HANDWRITTEN-CONTRACT` accepts code-first contracts. A contract file
  under `contracts/` now counts as covered when a `[[zone]]` names it as
  generated output (`path` equal to the file or a directory holding it, with
  `write_policy = "generated_output"`) and a test or gate lane runs the zone's
  `command`, as well as in the previous contract-first shape where a zone's
  `source` names the contract. Repositories whose typed sources generate the
  schema no longer have to mislabel the generated file as the source; a
  `generated_output` zone with no drift check is still flagged.
- CI evidence is detected through a CI-provider abstraction
  (`audit::ci_provider`) instead of matching the path `.github/workflows/`.
  GitHub Actions behaves as before; a repository gated by the jeryu forge now
  earns the audit-lane, security-in-CI, tool-adoption and release-automation CI
  evidence from its checked-in `.jeryu/ci.toml` declaration (jeryu's schema
  `"2"`: `schema_version = "2"`, `provider = "jeryu"`, `[[lane]]` entries),
  cross-checked against the real content of the lane it names. Repair routes
  point forge-gated repositories at their declaration instead of at
  `.github/workflows/jankurai.yml`. Older schema-`"1"` `.jeryu/ci.toml` files
  parse but are not evidence; `agent/ci.toml` is not read. See
  `docs/ci-providers.md`.
- Public auditor identity is `1.7.1`. Standard `0.9.0` and schema `1.9.0` are unchanged.
  A stored scan whose `last_full_auditor_version` differs from this identity runs a full scan.
- Treat `reviewed_manual` generated-zone entries as review-governed source
  artifacts while retaining existence, metadata, and generator-only guards.

### Added

- Root `Justfile` command surface with `setup`, `fast`, `check`, `security`, and
  `audit` lanes for one-command setup and validation.
- GitHub Actions CI (`.github/workflows/ci.yml`) with build, security, and
  jankurai audit jobs, all third-party actions pinned to commit SHAs.
- Pinned CI lane scripts under `ops/ci/` and local entrypoints under `scripts/`.
- Agent-readable documentation: `README.md`, `docs/architecture.md`,
  `docs/testing.md`, `docs/boundaries.md`, `docs/release.md`, and
  `docs/exceptions.md`.
- Agent control plane under `agent/`: `audit-policy.toml`, `owner-map.json`,
  `test-map.json`, `boundaries.toml`, `generated-zones.toml`,
  `security-policy.toml`, `tool-adoption.toml`, `coverage-sources.toml`,
  `copy-code-allowlist.toml`, and `proof-lanes.toml`, scoped to this repo.
- `.cargo/config.toml`, `VERSION`, and `rust-toolchain.toml` for hermetic,
  reproducible builds.

## [1.7.0] - 2026-06-12

### Added

- Initial split-family extraction of the shared `jankurai-audit-kernel` crate
  (model, scan, rules, caps, boundaries, validation, render) and its JSON Schema
  contracts from `jankurai-core`.
