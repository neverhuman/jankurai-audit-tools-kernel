//! CI-provider abstraction for evidence detection.
//!
//! Every CI-evidence detector used to key on the literal path
//! `.github/workflows/`, so a repository whose gate is enforced by a forge that
//! never executes committed workflow files got no CI credit at all — and
//! committing a workflow the forge ignores would have been a false green.
//!
//! This module is the single place that answers "what is this repository's CI,
//! and what does it actually run". Two providers are supported:
//!
//! * [`CiProvider::GithubActions`] — workflow files under `.github/workflows/`.
//!   Commands come from parsing the workflow YAML (unchanged behaviour).
//! * [`CiProvider::Jeryu`] — a forge whose checks are configured forge-side and
//!   are not committed as workflow files. Evidence comes from the checked-in
//!   declaration at [`JERYU_DECLARATION_PATH`] (jeryu's own schema, version
//!   [`JERYU_SCHEMA_VERSION`]) that names the provider and its required lanes,
//!   cross-checked against the lane's real content.
//!
//! The cross-check is what keeps the declaration honest: a lane earns credit
//! only through the text of the recipe or script it resolves to, so a
//! declaration naming a lane that does not exist, or a lane that does not run
//! the tool, earns nothing. Detection is deterministic and offline: it reads
//! only files already in the source inventory and never consults a network.

use crate::model::FileInfo;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeSet;

/// A recognised CI provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CiProvider {
    GithubActions,
    Jeryu,
}

impl CiProvider {
    pub fn id(self) -> &'static str {
        match self {
            CiProvider::GithubActions => "github-actions",
            CiProvider::Jeryu => "jeryu",
        }
    }

    /// The path a repair route should point a repository of this provider at
    /// when it needs a CI lane that runs the audit.
    pub const fn ci_anchor_path(self) -> &'static str {
        match self {
            CiProvider::GithubActions => ".github/workflows/jankurai.yml",
            CiProvider::Jeryu => JERYU_DECLARATION_PATH,
        }
    }
}

/// The one checked-in declaration recognised for the jeryu provider. The file
/// and its schema are owned by jeryu; the audit only reads it. It is also the
/// path `jankurai ci install --jeryu` writes.
pub const JERYU_DECLARATION_PATH: &str = ".jeryu/ci.toml";

/// The declaration schema version that carries lanes. Older `.jeryu/ci.toml`
/// files (version `"1"`, with flags such as `github_actions_required` and no
/// `provider`) still parse but are not jeryu CI evidence.
pub const JERYU_SCHEMA_VERSION: &str = "2";

const MAX_DECLARATION_BYTES: usize = 64 * 1024;
const MAX_LANES: usize = 32;
const MAX_EXPANSION_DEPTH: usize = 4;

/// One declared CI lane that resolved to real content in the repository.
#[derive(Debug, Clone)]
pub struct CiLane {
    /// Lane name from the declaration, e.g. `required`.
    pub name: String,
    /// Command the forge runs for the lane, e.g. `just required`.
    pub command: String,
    /// Repository path the lane resolved through, e.g. `Justfile`.
    pub source: String,
    /// Lowercased text of the recipe or script the lane runs, including the
    /// scripts it calls.
    pub text: String,
    /// Tools the declaration claims the lane runs.
    pub declared_tools: Vec<String>,
    /// Declared tools confirmed by `text`. Only these are ever credited.
    pub verified_tools: Vec<String>,
    /// Declared tools absent from `text`. Never credited; useful in findings.
    pub unverified_tools: Vec<String>,
}

/// What this repository's CI is, and what its lanes really run.
#[derive(Debug, Clone, Default)]
pub struct CiSurface {
    pub providers: Vec<CiProvider>,
    pub lanes: Vec<CiLane>,
    /// Declared lanes that could not be resolved to repository content.
    pub unresolved_lanes: Vec<String>,
}

impl CiSurface {
    pub fn has(&self, provider: CiProvider) -> bool {
        self.providers.contains(&provider)
    }

    /// The provider whose repair route a finding should point at. GitHub
    /// Actions wins when both are present because a committed workflow is the
    /// surface the repository can actually edit to fix the lane.
    pub fn primary(&self) -> CiProvider {
        if self.has(CiProvider::GithubActions) || !self.has(CiProvider::Jeryu) {
            CiProvider::GithubActions
        } else {
            CiProvider::Jeryu
        }
    }
}

// --- Path predicates -------------------------------------------------------
//
// Detectors call these instead of matching path strings, so adding a provider
// is a change in one module.

/// A GitHub Actions workflow file, by path only.
pub fn is_github_workflow_path(path: &str) -> bool {
    path.to_ascii_lowercase().starts_with(".github/workflows/")
}

/// A GitHub Actions workflow file whose content is YAML. Rules that parse or
/// line-scan workflow YAML use this.
pub fn is_github_workflow_yaml_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    is_github_workflow_path(&lower) && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
}

/// A checked-in jeryu declaration.
pub fn is_jeryu_declaration_path(path: &str) -> bool {
    path.eq_ignore_ascii_case(JERYU_DECLARATION_PATH)
}

/// A path that carries this repository's CI evidence for some supported
/// provider: the workflow files GitHub Actions executes, or the declaration
/// that names the jeryu lanes.
pub fn is_ci_evidence_path(path: &str) -> bool {
    is_github_workflow_path(path) || is_jeryu_declaration_path(path)
}

/// Any recognised CI configuration file, including providers whose evidence the
/// kernel does not parse. Used by rules that scan CI config for bad behaviour.
pub fn is_ci_config_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    is_github_workflow_yaml_path(&lower)
        || is_jeryu_declaration_path(&lower)
        || lower == ".gitlab-ci.yml"
        || lower == "bitbucket-pipelines.yml"
        || lower == "jenkinsfile"
        || lower == "azure-pipelines.yml"
        || lower.starts_with(".circleci/") && lower.ends_with("config.yml")
        || lower.starts_with(".buildkite/") && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
        || lower.contains("buildkite") && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
}

// --- Declaration ------------------------------------------------------------

/// The declaration as written. Every field is optional at parse time so an
/// older or foreign `.jeryu/ci.toml` reads cleanly and is then rejected by
/// [`DeclarationFile::is_jeryu_v2`] instead of failing to parse.
#[derive(Deserialize)]
struct DeclarationFile {
    #[serde(default)]
    schema_version: Option<toml::Value>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    lane: Vec<DeclaredLane>,
}

impl DeclarationFile {
    fn is_jeryu_v2(&self) -> bool {
        let version = matches!(
            &self.schema_version,
            Some(toml::Value::String(version)) if version == JERYU_SCHEMA_VERSION
        );
        let provider = self
            .provider
            .as_deref()
            .is_some_and(|provider| provider.eq_ignore_ascii_case(CiProvider::Jeryu.id()));
        version && provider
    }
}

#[derive(Deserialize)]
struct DeclaredLane {
    name: String,
    command: String,
    #[serde(default)]
    runs: Vec<String>,
}

/// Detect the providers of a repository and resolve its declared lanes.
pub fn detect(files: &[FileInfo]) -> CiSurface {
    let mut surface = CiSurface::default();
    if files
        .iter()
        .any(|file| is_github_workflow_yaml_path(&file.rel_path))
    {
        surface.providers.push(CiProvider::GithubActions);
    }
    let Some(declaration) = jeryu_declaration(files) else {
        return surface;
    };
    for declared in declaration.lane.into_iter().take(MAX_LANES) {
        match resolve_lane(files, &declared) {
            Some(lane) => surface.lanes.push(lane),
            None => surface.unresolved_lanes.push(declared.name),
        }
    }
    if !surface.lanes.is_empty() {
        surface.providers.push(CiProvider::Jeryu);
    }
    surface
}

fn jeryu_declaration(files: &[FileInfo]) -> Option<DeclarationFile> {
    let file = files
        .iter()
        .find(|file| file.rel_path == JERYU_DECLARATION_PATH)?;
    if file.text.len() > MAX_DECLARATION_BYTES {
        return None;
    }
    let parsed = toml::from_str::<DeclarationFile>(&file.text).ok()?;
    parsed.is_jeryu_v2().then_some(parsed)
}

fn resolve_lane(files: &[FileInfo], declared: &DeclaredLane) -> Option<CiLane> {
    let (source, body) = lane_body(files, &declared.command)?;
    let text = expand(files, &body, &mut BTreeSet::new(), 0);
    let (verified_tools, unverified_tools) = declared.runs.iter().cloned().partition(|tool| {
        let needle = tool.to_ascii_lowercase();
        !needle.is_empty() && text.contains(&needle)
    });
    Some(CiLane {
        name: declared.name.clone(),
        command: declared.command.clone(),
        source,
        text,
        declared_tools: declared.runs.clone(),
        verified_tools,
        unverified_tools,
    })
}

/// Resolve a lane command to the repository content it runs. Returns the
/// repository path the lane entered through and the raw body text.
fn lane_body(files: &[FileInfo], command: &str) -> Option<(String, String)> {
    let words: Vec<&str> = command.split_whitespace().collect();
    match words.as_slice() {
        ["just", recipe, ..] => {
            let file = files
                .iter()
                .find(|file| file.name == "Justfile" || file.name == "justfile")?;
            Some((file.rel_path.clone(), recipe_body(&file.text, recipe)?))
        }
        ["make", target, ..] => {
            let file = files
                .iter()
                .find(|file| file.name == "Makefile" || file.name == "makefile")?;
            Some((file.rel_path.clone(), recipe_body(&file.text, target)?))
        }
        ["bash", script, ..] | ["sh", script, ..] => {
            let file = files.iter().find(|file| file.rel_path == *script)?;
            Some((file.rel_path.clone(), file.text.clone()))
        }
        ["npm", "test" | "t", ..] => package_lane(files, "test", true),
        ["npm", "run" | "run-script", script, ..] => package_lane(files, script, true),
        ["pnpm", "run", script, ..] | ["yarn", "run", script, ..] => {
            package_lane(files, script, false)
        }
        ["yarn", script, ..] => package_lane(files, script, false),
        _ => None,
    }
}

/// Resolve a package-manager lane (`npm test`, `npm run <script>`,
/// `pnpm run <script>`, `yarn <script>`) through the root `package.json`
/// `scripts`. The script's text is the lane's text, followed into the scripts
/// it runs in turn the same way a `just` recipe is followed into its
/// dependencies: only scripts that exist, bounded by [`MAX_EXPANSION_DEPTH`],
/// each visited once. `npm` also runs a script's `pre<name>` and `post<name>`
/// hooks, so those are part of an npm lane.
fn package_lane(files: &[FileInfo], script: &str, npm_hooks: bool) -> Option<(String, String)> {
    let file = files.iter().find(|file| file.rel_path == "package.json")?;
    let parsed = serde_json::from_str::<serde_json::Value>(&file.text).ok()?;
    let scripts: std::collections::BTreeMap<String, String> = parsed
        .get("scripts")?
        .as_object()?
        .iter()
        .filter_map(|(name, body)| Some((name.clone(), body.as_str()?.to_string())))
        .collect();
    let body = script_closure(&scripts, script, npm_hooks, &mut BTreeSet::new(), 0)?;
    Some((file.rel_path.clone(), body))
}

fn script_closure(
    scripts: &std::collections::BTreeMap<String, String>,
    name: &str,
    npm_hooks: bool,
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> Option<String> {
    let script = scripts.get(name)?;
    visited.insert(name.to_string());
    let mut body = String::new();
    let hooks = if npm_hooks {
        [format!("pre{name}"), format!("post{name}")]
    } else {
        [String::new(), String::new()]
    };
    let follow = |target: &str, body: &mut String, visited: &mut BTreeSet<String>| {
        if depth < MAX_EXPANSION_DEPTH && !target.is_empty() && !visited.contains(target) {
            if let Some(text) = script_closure(scripts, target, npm_hooks, visited, depth + 1) {
                body.push_str(&text);
            }
        }
    };
    follow(&hooks[0], &mut body, visited);
    body.push_str(script);
    body.push('\n');
    for reference in script_references(script) {
        follow(&reference, &mut body, visited);
    }
    follow(&hooks[1], &mut body, visited);
    Some(body)
}

/// Script names a package script runs through a package manager:
/// `npm run x`, `npm run-script x`, `npm test`, `pnpm run x`, `pnpm x`,
/// `yarn run x`, `yarn x`, and the names passed to `run-s` / `run-p` /
/// `npm-run-all`. Names that are not scripts are dropped by the caller.
fn script_references(text: &str) -> Vec<String> {
    let words: Vec<&str> = text
        .split(|ch: char| ch.is_whitespace() || ";&|()".contains(ch))
        .map(|word| word.trim_matches(|ch| ch == '"' || ch == '\''))
        .filter(|word| !word.is_empty())
        .collect();
    let mut references = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let next = words.get(index + 1).copied().unwrap_or_default();
        let after = words.get(index + 2).copied().unwrap_or_default();
        match (*word, next) {
            ("npm", "run" | "run-script") | ("pnpm" | "yarn", "run") => {
                references.push(after.to_string())
            }
            ("npm", "test" | "t") => references.push("test".into()),
            ("pnpm" | "yarn", name) => references.push(name.to_string()),
            ("run-s" | "run-p" | "npm-run-all", _) => references.extend(
                words[index + 1..]
                    .iter()
                    .filter(|name| !name.starts_with('-'))
                    .take(MAX_LANES)
                    .map(|name| name.to_string()),
            ),
            _ => {}
        }
    }
    references
}

/// Body of a `<name>:`-headed recipe or target as written in a Justfile or
/// Makefile: the indented lines that follow the header, followed by the bodies
/// of the recipes it depends on. A gate written as `required: fast security`
/// runs `fast` and `security` first, so their commands are the lane's commands.
/// Dependencies are followed only when a recipe of that name exists, bounded by
/// [`MAX_EXPANSION_DEPTH`] and visited once each.
fn recipe_body(text: &str, name: &str) -> Option<String> {
    recipe_closure(text, name, &mut BTreeSet::new(), 0)
}

fn recipe_closure(
    text: &str,
    name: &str,
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> Option<String> {
    let header = format!("{name}:");
    let mut lines = text.lines();
    let header_line = lines.find(|line| {
        !line.starts_with([' ', '\t'])
            && line.trim_end().starts_with(&header)
            && !line[header.len()..].starts_with('=')
    })?;
    visited.insert(name.to_string());
    let mut body = String::new();
    for line in lines {
        if !line.trim().is_empty() && !line.starts_with([' ', '\t']) {
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    if depth >= MAX_EXPANSION_DEPTH {
        return Some(body);
    }
    let dependencies = header_line[header.len()..]
        .split('#')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .filter(|word| {
            word.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    for dependency in dependencies {
        if visited.contains(&dependency) {
            continue;
        }
        if let Some(dependency_body) = recipe_closure(text, &dependency, visited, depth + 1) {
            body.push_str(&dependency_body);
        }
    }
    Some(body)
}

/// Follow the lane body one hop at a time into the files it runs, so a lane
/// whose recipe delegates to `bash scripts/<lane>.sh` still exposes the
/// commands that script runs. Output is lowercased for needle matching.
fn expand(files: &[FileInfo], body: &str, visited: &mut BTreeSet<String>, depth: usize) -> String {
    let mut text = body.to_ascii_lowercase();
    if depth >= MAX_EXPANSION_DEPTH {
        return text;
    }
    for word in body.split_whitespace() {
        let candidate = word.trim_matches(|ch| ch == '"' || ch == '\'');
        if !candidate.contains('/') && !candidate.ends_with(".sh") {
            continue;
        }
        let Some(file) = files.iter().find(|file| file.rel_path == candidate) else {
            continue;
        };
        if !visited.insert(candidate.to_string()) {
            continue;
        }
        text.push('\n');
        text.push_str(&expand(files, &file.text, visited, depth + 1));
    }
    text
}

// --- Evidence ---------------------------------------------------------------

/// Command lines the repository's CI runs, per provider.
pub fn ci_command_lines(files: &[FileInfo]) -> Vec<String> {
    let mut lines = Vec::new();
    for file in files
        .iter()
        .filter(|file| is_github_workflow_yaml_path(&file.rel_path))
    {
        lines.extend(github_workflow_commands(&file.text));
    }
    lines.extend(jeryu_lane_command_lines(files));
    lines
}

/// Command lines of the verified jeryu lanes. Empty unless the repository has a
/// declaration whose lanes resolve to real content.
pub fn jeryu_lane_command_lines(files: &[FileInfo]) -> Vec<String> {
    let mut lines = Vec::new();
    for lane in detect(files).lanes {
        lines.extend(shell_lines(&lane.text));
    }
    lines
}

/// Lowercased text of every CI-evidence surface: workflow files GitHub Actions
/// executes plus the resolved content of the declared jeryu lanes.
pub fn ci_evidence_text(files: &[FileInfo]) -> String {
    let mut text = String::new();
    for file in files
        .iter()
        .filter(|file| is_github_workflow_path(&file.rel_path))
    {
        text.push('\n');
        text.push_str(&file.text.to_ascii_lowercase());
    }
    for lane in detect(files).lanes {
        text.push('\n');
        text.push_str(&lane.text);
    }
    text
}

/// Text of the GitHub Actions workflow files only. Artifact-upload evidence is
/// specific to that provider.
pub fn github_workflow_text(files: &[FileInfo]) -> String {
    let mut text = String::new();
    for file in files
        .iter()
        .filter(|file| is_github_workflow_path(&file.rel_path))
    {
        text.push('\n');
        text.push_str(&file.text.to_ascii_lowercase());
    }
    text
}

/// True when the repository has GitHub Actions workflow files, by path only.
pub fn has_github_workflows(files: &[FileInfo]) -> bool {
    files
        .iter()
        .any(|file| is_github_workflow_path(&file.rel_path))
}

/// Markers that show a CI lane really reuses a build or dependency cache. This
/// is the one list the jeryu side of the "CI cache hint" reads; it is kept
/// conservative on purpose. The bare word `cache` is not a marker: it appears in
/// comments, paths and `rm -rf` lines that cache nothing.
pub const CI_CACHE_MARKERS: &[&str] = &[
    "sccache",
    "rustc_wrapper",
    "cargo_target_dir",
    "actions/cache",
    "rust-cache",
    "npm_config_cache",
    "pip_cache_dir",
    "uv_cache_dir",
    "turbo_cache_dir",
    "ccache",
];

/// Flags that ask a tool to use a cache: `--cache`, `--cache=<dir>`,
/// `--cache-dir`, `--cache-from`, `--cache-to`, `--cache-location`. Matched
/// per token so `git diff --cached` and `--no-cache` are not cache use.
const CI_CACHE_FLAGS: &[&str] = &[
    "--cache",
    "--cache-dir",
    "--cache-from",
    "--cache-to",
    "--cache-location",
];

/// Cache markers found in the command lines of `text` (comment lines and
/// trailing ` #` comments are ignored). Returns each marker once, in list order.
pub fn cache_markers_in(text: &str) -> Vec<&'static str> {
    let mut found = BTreeSet::new();
    for line in shell_lines(text) {
        let command = line.split(" #").next().unwrap_or_default();
        for marker in CI_CACHE_MARKERS {
            if command.contains(marker) {
                found.insert(*marker);
            }
        }
        for token in command.split_whitespace() {
            let flag = token.split('=').next().unwrap_or_default();
            if let Some(matched) = CI_CACHE_FLAGS.iter().find(|candidate| **candidate == flag) {
                found.insert(*matched);
            }
        }
    }
    CI_CACHE_MARKERS
        .iter()
        .chain(CI_CACHE_FLAGS)
        .copied()
        .filter(|marker| found.contains(marker))
        .collect()
}

/// Cache markers in the resolved text of the declared jeryu lanes. Empty unless
/// a lane resolves and really runs something that uses a cache.
pub fn jeryu_lane_cache_markers(files: &[FileInfo]) -> Vec<&'static str> {
    let mut markers = Vec::new();
    for lane in detect(files).lanes {
        for marker in cache_markers_in(&lane.text) {
            if !markers.contains(&marker) {
                markers.push(marker);
            }
        }
    }
    markers
}

/// `run:` and `uses:` lines of a GitHub Actions workflow.
pub fn github_workflow_commands(text: &str) -> Vec<String> {
    let parsed = match serde_yaml::from_str::<YamlValue>(text) {
        Ok(parsed) => parsed,
        Err(_) => return vec![],
    };
    let mut lines = Vec::new();
    let Some(jobs) = parsed.get("jobs").and_then(|jobs| jobs.as_mapping()) else {
        return lines;
    };
    for job in jobs.values() {
        let Some(steps) = job.get("steps").and_then(|steps| steps.as_sequence()) else {
            continue;
        };
        for step in steps {
            if let Some(run) = step.get("run").and_then(|run| run.as_str()) {
                lines.extend(shell_lines(run));
            }
            if let Some(uses) = step.get("uses").and_then(|uses| uses.as_str()) {
                lines.push(format!("uses: {}", uses.to_ascii_lowercase()));
            }
        }
    }
    lines
}

pub(crate) fn shell_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .filter(|line| !line.starts_with("//"))
        .filter(|line| !line.starts_with("echo "))
        .filter(|line| *line != "{" && *line != "}")
        .map(|line| line.to_ascii_lowercase())
        .collect()
}

// --- Repair routes ----------------------------------------------------------

/// Where a repository of this provider declares the lane that runs the audit.
pub fn audit_lane_anchor_path(files: &[FileInfo]) -> &'static str {
    detect(files).primary().ci_anchor_path()
}

/// A soft finding for a declared lane that resolves to no repository content.
/// Such a lane earns nothing; reporting it keeps a typo in `command` visible.
/// Findings built from this are `low` severity and routed at
/// [`JERYU_DECLARATION_PATH`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedLaneFinding {
    pub lane: String,
    pub problem: String,
    pub fix: String,
    pub evidence: Vec<String>,
}

/// One [`UnresolvedLaneFinding`] per declared lane that did not resolve.
pub fn unresolved_lane_findings(files: &[FileInfo]) -> Vec<UnresolvedLaneFinding> {
    detect(files)
        .unresolved_lanes
        .into_iter()
        .map(|lane| UnresolvedLaneFinding {
            problem: format!("declared CI lane `{lane}` does not resolve to repository content"),
            fix: format!(
                "point the lane's `command` in `{JERYU_DECLARATION_PATH}` at a `just` recipe, `make` target, script path or package.json script that exists, or remove the lane; an unresolved lane earns no CI credit"
            ),
            evidence: vec![format!(
                "lane `{lane}` resolved to no recipe, target, script or package.json script"
            )],
            lane,
        })
        .collect()
}

/// Where a CI-cap finding (no audit lane, no security lane, no scans) points:
/// the declaration of a forge-gated repository, else the workflow directory.
pub fn ci_findings_path(files: &[FileInfo]) -> &'static str {
    match detect(files).primary() {
        CiProvider::GithubActions => ".github/workflows",
        CiProvider::Jeryu => JERYU_DECLARATION_PATH,
    }
}

/// Provider-correct repair instruction for "CI does not run the audit lane".
/// A forge-gated repository is never told to add a workflow file the forge
/// would not execute.
pub fn audit_lane_fix(files: &[FileInfo]) -> String {
    match detect(files).primary() {
        CiProvider::GithubActions => "add a CI job that runs `jankurai audit . --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md` and uploads both artifacts".into(),
        CiProvider::Jeryu => format!(
            "add the audit to the lane your forge runs and declare it in `{JERYU_DECLARATION_PATH}`: the lane command must really run `jankurai audit . --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md`"
        ),
    }
}

/// The declaration `jankurai ci install --jeryu` writes. Rendered here so the
/// installer and the detector cannot drift apart.
pub fn jeryu_declaration_template(lane: &str, command: &str, runs: &[&str]) -> String {
    let runs = runs
        .iter()
        .map(|tool| format!("\"{tool}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "# CI provider declaration. The forge configures its checks forge-side,\n\
         # so there is no committed workflow file to read; this names the lanes it\n\
         # runs. Credit comes from the lane's real content, never from this file.\n\
         schema_version = \"{JERYU_SCHEMA_VERSION}\"\n\
         provider = \"jeryu\"\n\
         \n\
         [[lane]]\n\
         name = \"{lane}\"\n\
         command = \"{command}\"\n\
         runs = [{runs}]\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(rel_path: &str, text: &str) -> FileInfo {
        FileInfo {
            rel_path: rel_path.into(),
            name: rel_path.rsplit('/').next().unwrap_or(rel_path).into(),
            suffix: String::new(),
            size: text.len() as u64,
            line_count: text.lines().count(),
            text: text.into(),
            is_generated: false,
            is_code: false,
        }
    }

    fn declaration() -> FileInfo {
        file(
            ".jeryu/ci.toml",
            "schema_version = \"2\"\nprovider = \"jeryu\"\n\n[[lane]]\nname = \"required\"\ncommand = \"just required\"\nruns = [\"jankurai audit\", \"gitleaks\"]\n",
        )
    }

    #[test]
    fn lane_credit_follows_the_script_the_recipe_calls() {
        let files = vec![
            declaration(),
            file("Justfile", "required:\n    bash scripts/gate.sh\n"),
            file(
                "scripts/gate.sh",
                "jankurai audit . --json target/jankurai/repo-score.json\ngitleaks detect\n",
            ),
        ];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::Jeryu));
        let lane = &surface.lanes[0];
        assert_eq!(lane.source, "Justfile");
        assert_eq!(lane.verified_tools, vec!["jankurai audit", "gitleaks"]);
        assert!(lane.unverified_tools.is_empty());
        assert!(ci_evidence_text(&files).contains("jankurai audit"));
    }

    #[test]
    fn declared_tools_absent_from_the_lane_are_not_credited() {
        let files = vec![
            declaration(),
            file("Justfile", "required:\n    cargo test --workspace\n"),
        ];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::Jeryu));
        assert!(surface.lanes[0].verified_tools.is_empty());
        assert_eq!(
            surface.lanes[0].unverified_tools,
            vec!["jankurai audit", "gitleaks"]
        );
        assert!(!ci_evidence_text(&files).contains("jankurai audit"));
    }

    #[test]
    fn a_declaration_naming_a_missing_lane_is_not_a_provider() {
        let files = vec![declaration(), file("Justfile", "fast:\n    cargo check\n")];
        let surface = detect(&files);
        assert!(!surface.has(CiProvider::Jeryu));
        assert_eq!(surface.unresolved_lanes, vec!["required"]);
        assert!(ci_evidence_text(&files).trim().is_empty());
    }

    #[test]
    fn another_providers_declaration_is_not_jeryu_evidence() {
        let files = vec![
            file(
                ".jeryu/ci.toml",
                "schema_version = \"2\"\nprovider = \"github-actions\"\n\n[[lane]]\nname = \"required\"\ncommand = \"just required\"\n",
            ),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        assert!(!detect(&files).has(CiProvider::Jeryu));
    }

    #[test]
    fn github_workflows_keep_their_own_route() {
        let files = vec![file(
            ".github/workflows/jankurai.yml",
            "jobs:\n  audit:\n    steps:\n      - run: jankurai audit .\n",
        )];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::GithubActions));
        assert_eq!(surface.primary(), CiProvider::GithubActions);
        assert_eq!(
            audit_lane_anchor_path(&files),
            ".github/workflows/jankurai.yml"
        );
        assert!(ci_command_lines(&files)
            .iter()
            .any(|line| line.contains("jankurai audit")));
    }

    #[test]
    fn forge_repositories_are_routed_at_their_declaration() {
        let files = vec![
            declaration(),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        assert_eq!(audit_lane_anchor_path(&files), ".jeryu/ci.toml");
        assert!(audit_lane_fix(&files).contains(".jeryu/ci.toml"));
        assert!(!audit_lane_fix(&files).contains(".github/workflows"));
    }

    #[test]
    fn rendered_declaration_is_detected_by_the_detector() {
        let rendered = jeryu_declaration_template("required", "just required", &["jankurai audit"]);
        let files = vec![
            file(".jeryu/ci.toml", &rendered),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::Jeryu));
        assert_eq!(surface.lanes[0].verified_tools, vec!["jankurai audit"]);
        assert!(rendered.contains("schema_version = \"2\""));
    }

    #[test]
    fn lane_credit_follows_the_recipes_the_gate_depends_on() {
        let files = vec![
            declaration(),
            file(
                "Justfile",
                "tool := \"x\"\nrequired: fast security # the gate\n\nfast:\n    cargo test\n\nsecurity: fast\n    cargo audit\n    gitleaks detect\n\nunused:\n    jankurai audit .\n",
            ),
        ];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::Jeryu));
        let lane = &surface.lanes[0];
        assert!(lane.text.contains("cargo test"));
        assert!(lane.text.contains("cargo audit"));
        assert_eq!(lane.verified_tools, vec!["gitleaks"]);
        assert_eq!(lane.unverified_tools, vec!["jankurai audit"]);
        assert_eq!(lane.text.matches("cargo test").count(), 1);
    }

    #[test]
    fn a_dependency_that_is_not_a_recipe_adds_nothing() {
        let files = vec![
            declaration(),
            file("Makefile", "required: build/out.bin\n\tcargo test\n"),
        ];
        let declared = DeclaredLane {
            name: "required".into(),
            command: "make required".into(),
            runs: vec![],
        };
        let lane = resolve_lane(&files, &declared).expect("make target resolves");
        assert_eq!(lane.text.trim(), "cargo test");
    }

    #[test]
    fn a_schema_version_1_declaration_parses_and_is_not_jeryu_evidence() {
        let files = vec![
            file(
                ".jeryu/ci.toml",
                "schema_version = \"1\"\ngithub_actions_required = true\n",
            ),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        let parsed: DeclarationFile = toml::from_str(&files[0].text).expect("v1 parses");
        assert!(!parsed.is_jeryu_v2());
        let surface = detect(&files);
        assert!(surface.providers.is_empty());
        assert!(surface.unresolved_lanes.is_empty());
        assert_eq!(
            audit_lane_anchor_path(&files),
            ".github/workflows/jankurai.yml"
        );
    }

    #[test]
    fn a_declaration_without_schema_version_2_is_not_jeryu_evidence() {
        let lanes =
            "provider = \"jeryu\"\n\n[[lane]]\nname = \"required\"\ncommand = \"just required\"\n";
        for header in ["", "schema_version = \"1\"\n", "schema_version = 2\n"] {
            let files = vec![
                file(".jeryu/ci.toml", &format!("{header}{lanes}")),
                file("Justfile", "required:\n    jankurai audit .\n"),
            ];
            assert!(!detect(&files).has(CiProvider::Jeryu), "{header:?}");
        }
    }

    #[test]
    fn the_agent_folder_is_not_a_declaration_path() {
        let text = declaration().text;
        let files = vec![
            file("agent/ci.toml", &text),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        assert!(!is_jeryu_declaration_path("agent/ci.toml"));
        assert!(!detect(&files).has(CiProvider::Jeryu));
    }

    fn lane(command: &str) -> DeclaredLane {
        DeclaredLane {
            name: "required".into(),
            command: command.into(),
            runs: vec![],
        }
    }

    const PACKAGE: &str = r#"{
  "name": "widget-lint",
  "scripts": {
    "pretest": "tsc -p .",
    "test": "npm run lint && vitest run",
    "posttest": "node tools/report.mjs",
    "lint": "eslint . && npm run lint:css",
    "lint:css": "stylelint src",
    "check": "run-s lint unit",
    "unit": "vitest run --coverage",
    "loop": "npm run loop2",
    "loop2": "npm run loop"
  }
}"#;

    #[test]
    fn npm_test_resolves_through_package_scripts_and_hooks() {
        let files = vec![
            file("package.json", PACKAGE),
            file("tools/report.mjs", "console.log('gitleaks report')\n"),
        ];
        let resolved = resolve_lane(&files, &lane("npm test")).expect("npm test resolves");
        assert_eq!(resolved.source, "package.json");
        for needle in [
            "tsc -p .",
            "vitest run",
            "eslint .",
            "stylelint src",
            "gitleaks report",
        ] {
            assert!(
                resolved.text.contains(needle),
                "{needle}: {}",
                resolved.text
            );
        }
        assert_eq!(resolved.text.matches("eslint .").count(), 1);
    }

    #[test]
    fn package_manager_lane_forms_all_resolve() {
        let files = vec![file("package.json", PACKAGE)];
        for command in [
            "npm run lint",
            "npm run-script lint",
            "pnpm run lint",
            "yarn lint",
            "yarn run lint",
        ] {
            let resolved = resolve_lane(&files, &lane(command)).expect(command);
            assert!(resolved.text.contains("stylelint src"), "{command}");
            // pnpm and yarn do not run npm's pre/post hooks
            assert!(!resolved.text.contains("tsc -p ."), "{command}");
        }
        let check = resolve_lane(&files, &lane("npm run check")).expect("run-s resolves");
        assert!(check.text.contains("eslint .") && check.text.contains("--coverage"));
    }

    #[test]
    fn package_lanes_are_bounded_and_need_a_real_script() {
        let files = vec![file("package.json", PACKAGE)];
        let looped = resolve_lane(&files, &lane("npm run loop")).expect("cycle terminates");
        assert_eq!(looped.text.matches("npm run loop2").count(), 1);
        assert!(resolve_lane(&files, &lane("npm run missing")).is_none());
        assert!(resolve_lane(&files, &lane("yarn install")).is_none());
        assert!(resolve_lane(&[], &lane("npm test")).is_none());
        let no_scripts = vec![file("package.json", "{\"name\": \"x\"}")];
        assert!(resolve_lane(&no_scripts, &lane("npm test")).is_none());
    }

    #[test]
    fn cache_markers_need_real_cache_use() {
        assert_eq!(
            cache_markers_in("export RUSTC_WRAPPER=sccache\ncargo test\n"),
            vec!["sccache", "rustc_wrapper", "ccache"]
        );
        assert_eq!(
            cache_markers_in("CARGO_TARGET_DIR=target/shared cargo build\n"),
            vec!["cargo_target_dir"]
        );
        assert_eq!(
            cache_markers_in("npm ci --cache .npm --prefer-offline\n"),
            vec!["--cache"]
        );
        assert_eq!(
            cache_markers_in("docker buildx build --cache-from type=local,src=.buildx .\n"),
            vec!["--cache-from"]
        );
        assert!(cache_markers_in("# warm the cache first\ncargo test\n").is_empty());
        assert!(cache_markers_in("cargo test # sccache would help\n").is_empty());
        assert!(
            cache_markers_in("rm -rf cache/\ngit diff --cached\ndocker build --no-cache .\n")
                .is_empty()
        );
    }

    #[test]
    fn lane_cache_markers_come_only_from_resolved_lanes() {
        let files = vec![
            declaration(),
            file("Justfile", "required:\n    # cache warm-up lives elsewhere\n    sccache --show-stats\n    cargo test\n\nother:\n    CARGO_TARGET_DIR=x cargo build\n"),
        ];
        assert_eq!(jeryu_lane_cache_markers(&files), vec!["sccache", "ccache"]);
        let comment_only = vec![
            declaration(),
            file("Justfile", "required:\n    # cache\n    cargo test\n"),
        ];
        assert!(jeryu_lane_cache_markers(&comment_only).is_empty());
        let undeclared = vec![file("Justfile", "required:\n    sccache cargo test\n")];
        assert!(jeryu_lane_cache_markers(&undeclared).is_empty());
    }
}
