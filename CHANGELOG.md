# Changelog

All notable changes to jankurai-tools-kernel are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The authoritative
version string lives in [`VERSION`](VERSION).

## [Unreleased]

### Changed

- `HLT-001` dead-language exceptions can use reviewed, owned, expiring
  `[[dead_language_allow]]` records scoped to paths. A hit covered by an active
  record leaves `scan::future_hostile_hits` (no finding, no cap) and is returned
  by `scan::future_hostile_covered_hits` for reporting; outside-scope, expired
  or incomplete records count again and name the record to renew. Cap
  membership comes from the typed match, `scan::future_hostile_scan_at` takes
  the evaluation date, and an active record wins over expired or incomplete
  ones. The legacy `[dead_language] allow_terms` table is still read, and this
  repository's policy keeps it until a released auditor reads the records.

## [1.7.3] - 2026-10-07

### Changed

- Public auditor identity is `1.7.3`. Standard `0.9.0` and schema `1.9.0` are
  unchanged. A stored scan whose `last_full_auditor_version` differs from this
  identity runs a full scan.

### Fixed

- `HLT-022-AUTHZ-ISOLATION-GAP` matches its surface terms (`owner_id`,
  `tenant_id`, `organization_id`, `org_id`, `rls`, `row level security`,
  `admin`) as whole identifier tokens, not substrings, so `rls` no longer fires
  inside `urls`, `checked_cdp_urls`, `cdpUrlSetting`, `docs_urls` or `URLs`.
  Lines are split on non-alphanumerics and at camelCase, digit and
  acronym-to-word boundaries. Multi-word terms match consecutive tokens
  (`tenantId`, `OWNER-ID`, `ROW LEVEL SECURITY`), a term also matches its
  plural, and `admin` also matches `administrator` and any token ending in
  `admin` (`superadmin`, `sysadmin`, `webadmin`, `orgAdmin`). An all-caps
  run is one token: `RLS` matches, but the acronym `IRLS` does not. Token
  matching drops a few substring hits: `tenant_identifier` and
  `owner_identity` no longer match `tenant_id`/`owner_id`, `administration` no
  longer matches `admin`, and a glued `enablerls` no longer matches `rls`
  (matching every token ending in `rls` would bring back `urls`).
- The negative proof that clears `HLT-022-AUTHZ-ISOLATION-GAP` uses the same
  token matching. A test file counts only when one line holds `wrong user`,
  `other user`, `non owner` (also `non-owner`, `nonOwner`), `forbidden`,
  `tenant isolation` or `rls` as consecutive identifier tokens, so `urls` or
  `cdpUrls` in a test no longer clears a real finding, and neither does
  `another user` or a phrase split across two lines. Like the surface terms,
  the phrases match across naming styles, so `wrongUser` and `nonOwner` count.
  Proof is still searched repo-wide, as before.
- A `jankurai:allow … expires=YYYY-MM-DD` comment now suppresses a finding only
  while its expiry date is today (UTC) or later. An expired, missing or
  malformed expiry (`expires=never`, `expires=2026-02-30`) no longer
  suppresses anything. Before, the date was checked for shape only, so a past
  date suppressed forever. This applies to every detector that reads the
  shared allow comment (HLT-010, HLT-023, HLT-031, comment hygiene, and the
  analyzers' web-security and repo-rot detectors). The date is the current
  UTC date, so the same commit can gain a finding on a later day once an allow
  expires. Smart scan runs a full scan when the last full scan was on an
  earlier UTC day, so a clean result is not carried past an expiry.
- `typescript.types.any-boundary` (HLT-031) again fires on an empty boundary
  call such as `response.json() as any` or `(await fetch()) as T`. The
  identifier-boundary check added below also applied to the call markers, so a
  `(` followed by `)` never matched; call markers now end at their `(`.
- `typescript.types.any-boundary` (HLT-031) no longer reads English prose as a
  TypeScript cast. The detector now runs on comment- and string-stripped source,
  requires a real `as` expression (an expression token before ` as ` and a type
  after it, never an `import`/`export` alias), and matches boundary markers as
  identifiers, so a JSDoc line mentioning `<input ...> value as the ...` or a
  word like `inputs` no longer fires. The suppression detector still reads raw
  lines, since `@ts-nocheck`/`eslint-disable` live in comments.

### Added

- `HLT-022-AUTHZ-ISOLATION-GAP` reports a SQL `CREATE POLICY <name> ON`
  statement as a surface when its `USING (`/`WITH CHECK (` clause follows on
  the same line or within the next three. The keywords must be separate words,
  so a `createPolicy(` call is not one. Standalone `.sql` product files, which
  are not code files, are now read for row-security statements only:
  `CREATE POLICY` and `ROW LEVEL SECURITY` (as in `ENABLE ROW LEVEL SECURITY`),
  ignoring `--` comments. Like every HLT-022 surface these come from product
  files, which exclude top-level `db/`, `migrations/`, `contracts/` and `ops/`,
  so SQL under application paths counts and top-level migration folders do
  not.

- A jeryu lane may be a package-manager command: `npm test`,
  `npm run <script>`, `npm run-script <script>`, `pnpm run <script>`,
  `yarn <script>`. It resolves through the root `package.json` `scripts` and
  follows the scripts it runs (bounded, each visited once; npm `pre`/`post`
  hooks included). Credit still comes only from the resolved text.
- `ci_provider::CI_CACHE_MARKERS`, `cache_markers_in` and
  `jeryu_lane_cache_markers`: the one conservative list of markers that show a
  resolved lane really uses a cache (sccache, `RUSTC_WRAPPER`,
  `CARGO_TARGET_DIR`, `--cache`/`--cache-dir`/`--cache-from`, ...). Comment
  lines and the bare word `cache` never count.
- `ci_provider::has_github_workflows`, used by the analyzers to decide whether
  workflow linting applies.
- `ci_provider::unresolved_lane_findings`: one soft finding per declared lane
  that does not resolve, routed at `.jeryu/ci.toml`. The audit pipeline in
  jankurai-core wires it in when it re-pins this kernel.

### Removed

- GitHub Actions workflows, the GitHub-only `ops/ci/aggregate.sh` /
  `scripts/ci-aggregate.mjs` job-inventory check and its test, and the
  workflow-lint (actionlint, zizmor) steps. GitHub is a publishing mirror only;
  CI runs on the forge and our hosts.

## [1.7.2] - 2026-10-02

### Changed

- `HLT-001` dead-language scanning uses the governed split.5 rule for Rust as
  for every other language: comment-only lines and trailing comments never
  count; string literals and active code do. The Rust comment/string lexer path
  is removed. (Owner decision X2.)
- `ci_provider::ci_findings_path` names the surface a CI-cap finding points at:
  `.jeryu/ci.toml` for a forge-gated repository, `.github/workflows` otherwise.
- `HLT-047` repair reason names the `@AGENTS.md` import instead of README links.
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
  parse but are not evidence; `agent/ci.toml` is not read. A `just`/`make`
  lane includes the recipes it depends on, so a dependency-only gate such as
  `required: fast security jankurai` is read in full. See
  `docs/ci-providers.md`.
- Public auditor identity is `1.7.2`. Standard `0.9.0` and schema `1.9.0` are unchanged.
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
