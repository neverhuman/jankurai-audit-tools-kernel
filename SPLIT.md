# jankurai-tools-kernel

Status: initial split-family extraction
Owner: Jankurai maintainers
Last reviewed: 2026-09-11
Applies to: jankurai-tools-kernel

## Role

Shared audit substrate (model, scan, rules, caps, boundaries, validation, render)
extracted from jankurai-core so the core CLI and sibling tools depend on one kernel.

## Repositories

- Historical Jeryu repo: `root/jankurai-tools-kernel`
- Primary GitHub repository: `neverhuman/jankurai-tools-kernel`
- Release tag pattern: `jankurai-tools-kernel-v1.7.0-split.0`
- Source extraction commit: `446af94`

## Split Rules

- GitHub is authoritative; Jeryu refs are retained as historical inputs.
- The hub `neverhuman/jankurai` controls product composition and releases.
- Release builds depend on immutable GitHub tags, not branches.
- Local development uses the hub `scripts/fuse.sh` output under `.fusion/`.
- Committed manifests must not depend on sibling checkout paths.
- Generated outputs are regenerated from their source contracts or build commands.

## Required Local Check

```bash
bash scripts/ci-local.sh required
```
