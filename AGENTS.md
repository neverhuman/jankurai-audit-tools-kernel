# jankurai-tools-kernel Agent Instructions

Read `SPLIT.md` first. This repository is one member of the Jankurai split family.

- Canonical GitHub repo: `neverhuman/jankurai-tools-kernel`.
- Primary remote: `github.com/neverhuman/jankurai-tools-kernel`.
- The hub `neverhuman/jankurai` controls product composition and releases.
- Do not add committed cross-repo `path = "../..."` dependencies. Use the hub fusion workspace for local path patches.
- Do not hand-edit generated artifacts listed in `agent/generated-zones.toml`.
- Run `bash scripts/ci-local.sh required` before handing off changes: it is the merge
  gate and runs `cargo metadata`, `cargo fmt --check`, `cargo clippy -D warnings` and
  `cargo nextest run` offline against the lock. `bash scripts/ci-local.sh fast` is the
  quick subset (`cargo check` + tests) for iteration.
