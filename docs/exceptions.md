# Agent exceptions and overrides

This document defines the agent-friendly exception pattern for
jankurai-tools-kernel: how an agent or maintainer requests, records, and bounds
an override of a standard rule. Exceptions are the only sanctioned way to deviate
from the audit baseline.

## Principle

The default answer is "follow the standard." An exception is a dated, owned,
expiring waiver for a specific rule on a specific path. Exceptions are data, not
prose: they live next to the code they govern and are reviewed on every audit.

## How to request an exception

1. Identify the exact `rule_id` and `path` the exception applies to (from the
   audit JSON `findings[]`).
2. Add an entry to the relevant `agent/*.toml` manifest. For boundary
   reclassifications use `agent/boundaries.toml`; for streaming runtimes use the
   `[[streaming_exception]]` block; for security policy use
   `agent/security-policy.toml`; for dead-language marker words that are
   load-bearing detector patterns use a `[[dead_language_allow]]` record in
   `agent/audit-policy.toml`.
3. Every exception entry MUST carry:
   - `owner` — the team or person accountable.
   - `classification` — e.g. `brownfield`, `temporary`, `vendor`.
   - `expires` — an ISO date after which the exception is invalid and the audit
     fails again.
   - `migration_path` — the concrete plan to remove the exception.

## Example

The kernel's HLT-001 detector source carries future-hostile marker strings as
detection patterns. The reviewed exception is path-scoped and expires:

```toml
[[dead_language_allow]]
name = "audit-kernel-detector-terms"
terms = ["todo", "legacy", "fallback"]
paths = ["crates/jankurai-audit-kernel/src/audit/scan.rs"]
owner = "tools"
expires = "2026-12-31"
reason = "HLT-001 detector source deliberately stores the marker vocabulary it scans for."
```

A covered hit remains visible in the audit report with the owner, expiry and
reason, but it does not apply the HLT-001 cap. A hit outside `paths`, or one
covered only by an expired or incomplete record, counts again and names the
record to renew.

Streaming exceptions use the same owned, dated pattern and are recorded in
[`agent/boundaries.toml`](../agent/boundaries.toml):

```toml
[[streaming_exception]]
runtime = "kafka"
classification = "brownfield"
owner = "tools"
expires = "2026-12-31"
migration_path = "Detector marker strings live only in the audit-kernel scan source ..."
```

## Override review

- Every exception is re-evaluated on each `just audit` run.
- An expired exception is treated as a hard finding, not a pass.
- Removing an exception requires deleting its entry and proving the underlying
  rule now passes on its own.

## What is never excepted

Secret leakage, destructive migrations without rollback, and hand-edits to
generated zones are never granted exceptions. Fix the underlying cause instead.
