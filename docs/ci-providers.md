# CI providers and CI evidence

Status: adopted
Owner: Jankurai maintainers
Last reviewed: 2026-10-02
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
  `make <target>` resolve to that recipe's body, `bash <path>` and `sh <path>`
  to that file. The body is then followed one hop at a time into the files it
  calls, so a thin recipe that delegates to `bash scripts/<lane>.sh` still
  exposes the commands that script runs.

**Credit comes only from the resolved lane text.** The declaration is a pointer,
never a claim that earns points:

* a declaration naming a lane that does not exist resolves to nothing, so the
  repository is not treated as jeryu-governed at all;
* a lane that exists but does not run a tool earns nothing for that tool, no
  matter what `runs` claims. Unconfirmed claims are reported on the lane as
  `unverified_tools` and are never credited.

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
