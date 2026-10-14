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
   load-bearing patterns use a `[[dead_language_allow]]` record in
   `agent/audit-policy.toml` (the legacy repo-wide `[dead_language]
   allow_terms` table is still read for old policies).
3. Every exception entry MUST carry:
   - `owner` — the team or person accountable.
   - `classification` — e.g. `brownfield`, `temporary`, `vendor`.
   - `expires` — an ISO date after which the exception is invalid and the audit
     fails again.
   - `migration_path` — the concrete plan to remove the exception.

## Example

A reviewed `[[dead_language_allow]]` record is path-scoped, owned and expires:

```toml
[[dead_language_allow]]
name = "iam-todo-grant"
terms = ["todo"]
paths = ["infra/iam"]
owner = "platform"
expires = "2026-12-31"
reason = "External IAM grant names use todo as a stable stand-in value."
```

A hit covered by an active record does not count toward HLT-001 (no finding, no
cap); the kernel returns it from `scan::future_hostile_covered_hits` with the
record's owner, expiry and reason so a report can show it. A hit outside
`paths`, or one matched only by an expired or incomplete record, counts again
and names the record to renew. When several records match, an active one wins
regardless of order in the file.

This repository's own detector vocabulary still uses the legacy
`[dead_language] allow_terms` table, because released auditors (1.7.3 and
earlier) read only that table. It moves to reviewed records, covering every
detector module under `crates/jankurai-audit-kernel/src/audit/`, once a
released auditor carries the record reader.

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
