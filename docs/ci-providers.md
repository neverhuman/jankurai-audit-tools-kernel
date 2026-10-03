# CI providers and CI evidence

Status: adopted
Owner: Jankurai maintainers
Last reviewed: 2026-10-03
Applies to: `crates/jankurai-audit-kernel/src/audit/ci_provider.rs`

Several caps and dimensions depend on what a repository's CI really runs: the
`no-jankurai-audit-lane-in-ci` cap (max 82), the
`no-secret-or-dependency-scanning-in-ci` cap (max 78), the "Jankurai tool
adoption and CI replacement" dimension, and release automation.

Every one of those detectors used to key on the literal path
`.github/workflows/`. That is wrong for a repository whose gate is enforced by a
forge that configures its checks forge-side and never executes committed
workflow files: the repository got no CI credit even when its CI genuinely ran
the audit, the security scans and the tests — and committing a workflow file the
forge ignores would have been a false green.

`audit::ci_provider` is now the single place that answers "what is this
repository's CI, and what does it actually run". Detectors call its predicates
instead of matching path strings.

## Providers

| Provider | Configuration read | Command evidence |
| --- | --- | --- |
| `github-actions` | `.github/workflows/*.yml` \| `*.yaml` | `run:` and `uses:` steps parsed from the workflow YAML |
| `jeryu` | a checked-in declaration (below) | the resolved content of the lanes the declaration names |

Rules that read provider-specific keys stay bound to their provider. Workflow
hardening (`permissions:`, `timeout-minutes:`, `concurrency:`, action pinning)
and artifact-upload evidence are GitHub Actions concepts, so a `jeryu`
declaration never attracts those findings and never earns upload credit.

## What counts as jeryu CI evidence

The declaration lives at `.jeryu/ci.toml`, and only there. The file and its
schema belong to jeryu (it is what `jeryu` writes for a repository); the audit
only reads it. Schema version `"2"` carries the lanes:

```toml
schema_version = "2"
provider = "jeryu"

[[lane]]
name = "required"
command = "just required"
runs = ["jankurai audit", "cargo audit", "gitleaks"]
```

* `schema_version` must be the string `"2"` and `provider` must be `jeryu`.
  Anything else is not jeryu evidence. Older schema-`"1"` files (flags such as
  `github_actions_required`, no `provider`, no lanes) still parse cleanly; they
  earn no credit and draw no finding of their own.
* `agent/ci.toml` is not read.
* each `[[lane]]` gives the lane's `name`, the `command` the forge runs, and the
  tools the lane claims to `run` (`runs` is optional).
* `command` is resolved offline against the repository: `just <recipe>` and
  `make <target>` resolve to that recipe's body plus the bodies of the recipes
  it depends on (`required: fast security` runs `fast` and `security`; a
  dependency that is not a recipe adds nothing), `bash <path>` and
  `sh <path>` to that file. Package-manager lanes resolve through the root
  `package.json` `scripts`: `npm test`, `npm run <script>`,
  `npm run-script <script>`, `pnpm run <script>`, `yarn <script>` and
  `yarn run <script>`. A script is followed into the scripts it runs in turn
  (`npm run x`, `pnpm x`, `yarn x`, `run-s`/`run-p` names) exactly as a recipe
  is followed into its dependencies: only scripts that exist, bounded, each
  visited once; an npm lane also includes the script's `pre`/`post` hooks. The
  body is then followed one hop at a time into the files it
  calls, so a thin recipe that delegates to `bash scripts/<lane>.sh` still
  exposes the commands that script runs.

**Credit comes only from the resolved lane text.** The declaration is a pointer,
never a claim that earns points:

* a declaration naming a lane that does not exist resolves to nothing, so the
  repository is not treated as jeryu-governed at all;
* a lane that exists but does not run a tool earns nothing for that tool, no
  matter what `runs` claims. Unconfirmed claims are reported on the lane as
  `unverified_tools` and are never credited.

A declared lane that resolves to nothing is reported as a soft (`low`)
finding at `.jeryu/ci.toml` naming the lane, so a typo in `command` is visible
instead of silently earning nothing. The kernel builds the finding text in
`ci_provider::unresolved_lane_findings`; the audit pipeline adds one finding per
entry.

## Dimension bonuses that read CI

Three dimension bonuses (in the analyzers crate) used to look only at
`.github/workflows/`. They now read the resolved lane text through this module
as well, and still never credit the declaration itself:

| Dimension | Bonus | GitHub Actions | jeryu |
| --- | --- | --- | --- |
| Proof lanes and test routing | +8 CI presence | workflow files present | at least one declared lane resolves |
| Build speed signals | +10 CI cache hint | workflow text mentions `cache` (unchanged) | resolved lane commands contain a marker from `ci_provider::CI_CACHE_MARKERS` (`sccache`, `RUSTC_WRAPPER`, `CARGO_TARGET_DIR`, `actions/cache`, `rust-cache`, `npm_config_cache`, `pip`/`uv`/`turbo` cache dirs, `ccache`) or a cache flag (`--cache`, `--cache-dir`, `--cache-from`, `--cache-to`, `--cache-location`) |
| Security and supply-chain posture | +8 workflow linting | `actionlint`/`zizmor` in the command or lane text | same; with no workflow files the check is not applicable |

The cache markers are matched on command lines only: comment lines and trailing
` #` comments are ignored, and the bare word `cache` is never a marker, so
`# warm the cache`, `rm -rf cache/`, `git diff --cached` and `--no-cache` earn
nothing.

Workflow linting (`actionlint`, `zizmor`) lints GitHub Actions workflow files,
so it applies only when the repository has some. Without workflow files — a
jeryu-gated repository, or one with no committed CI — the check is **not
applicable**, following the same principle as the Data truth dimension for a
repository with no database: it earns no points (no free bonus), and the
"complete operational security command posture" bonus is computed from the
checks that do apply, so the missing linter is not a hidden penalty either. A
lint tool found in the command or lane text still earns the points.

Detection is deterministic and offline. It reads only files already in the
source inventory, never the network, so the same commit always scores the same.
When the audit itself runs inside the forge, the forge's own check-runs for the
head are a further confirmation the forge may apply; the kernel never depends on
them.

## Repair routes

`ci_provider::audit_lane_anchor_path` and `ci_provider::audit_lane_fix` return
the provider-correct anchor and instruction, and
`finding_builder::dimension_soft_route_for` routes a below-floor dimension
through them. A forge-gated repository is pointed at its declaration and its
lane; it is never told to add `.github/workflows/jankurai.yml`. With no provider
detected, the routes keep the GitHub Actions default.

`ci_provider::jeryu_declaration_template` renders the declaration that
`jankurai ci install --jeryu` writes, so the installer and the detector cannot
drift apart.
