# jankurai-tools-kernel Architecture

`jankurai-tools-kernel` is the shared audit substrate of the Jankurai split
family. It ships one crate, `jankurai-audit-kernel`, which holds the model,
filesystem scan, language and repository rules, caps, boundary checks,
validation, and render layers that the `jankurai` CLI and its sibling tools
depend on. The product standard the family defines is:

```text
Rust core + TypeScript/React/Vite product surface + PostgreSQL truth
+ generated contracts + exception-only Python AI/data service
```

New implementation is Rust-first. Agents must not write Python for repo tools,
proof lanes, product services, general backend glue, authorization, or
production database writes. Python is allowed only for rare advanced ML/data
library work that has no practical Rust/TypeScript alternative, stays boxed to
`python/ai-service`, and carries a dated exception.

## Crate layout

| Path | Role |
| --- | --- |
| `crates/jankurai-audit-kernel/src/model.rs` | shared audit data model |
| `crates/jankurai-audit-kernel/src/audit/` | filesystem scan, language rules, caps, finding builders |
| `crates/jankurai-audit-kernel/src/boundaries/` | per-stack boundary manifests and checks |
| `crates/jankurai-audit-kernel/src/commands/` | shared command context data |
| `crates/jankurai-audit-kernel/src/report/` | proof and report rendering |
| `crates/jankurai-audit-kernel/src/render.rs` | Markdown/JSON render surface |
| `crates/jankurai-audit-kernel/src/validation.rs` | schema and manifest validation |
| `schemas/` | 67 JSON Schemas for the auditor's artifacts |

## Detection-pattern source

The kernel's scan and language-rule modules are *detector definitions*: they
carry the literal marker strings (for example `unsafe`, `transmute`,
`placeholder`, `rdkafka`, `innerhtml`) that the auditor searches for in other
repositories. These markers are pattern data, not live hazardous usage. The
upstream `jankurai` auditor excludes its own detector crates from the
product-code scan; in this extracted repo the same intent is expressed through
`agent/audit-policy.toml` (`[dead_language] allow_terms`) and the boundary and
exception manifests under `agent/`.

## Ownership and proof routing

Agents should prefer `agent/owner-map.json` and `agent/test-map.json` for
changes, then route to the smallest proof lane in `agent/proof-lanes.toml`.

- `agent/owner-map.json` assigns an owner to every top-level path.
- `agent/test-map.json` routes each owned path to a deterministic proof command.
- `agent/boundaries.toml` declares the Rust domain boundary and exceptions.
- `agent/generated-zones.toml` declares the only generated tree (`target/`).
