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
//!   are not committed as workflow files. Evidence comes from a checked-in
//!   declaration (see [`JERYU_DECLARATION_PATHS`]) that names the provider and
//!   its required lanes, cross-checked against the lane's real content.
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
            CiProvider::Jeryu => JERYU_PRIMARY_DECLARATION_PATH,
        }
    }
}

/// Checked-in declaration paths recognised for the jeryu provider. Both spell
/// the same schema; `agent/ci.toml` keeps CI policy with the rest of the agent
/// control plane, `.jeryu/ci.toml` suits repositories that group forge config.
pub const JERYU_DECLARATION_PATHS: &[&str] = &["agent/ci.toml", ".jeryu/ci.toml"];

/// The declaration path `jankurai ci install --jeryu` writes.
pub const JERYU_PRIMARY_DECLARATION_PATH: &str = "agent/ci.toml";

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
    let lower = path.to_ascii_lowercase();
    JERYU_DECLARATION_PATHS.contains(&lower.as_str())
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

#[derive(Deserialize)]
struct DeclarationFile {
    provider: String,
    #[serde(default)]
    lane: Vec<DeclaredLane>,
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
    for path in JERYU_DECLARATION_PATHS {
        let Some(file) = files.iter().find(|file| file.rel_path == *path) else {
            continue;
        };
        if file.text.len() > MAX_DECLARATION_BYTES {
            continue;
        }
        let Ok(parsed) = toml::from_str::<DeclarationFile>(&file.text) else {
            continue;
        };
        if parsed.provider.eq_ignore_ascii_case(CiProvider::Jeryu.id()) {
            return Some(parsed);
        }
    }
    None
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
        _ => None,
    }
}

/// Body of a `<name>:`-headed recipe or target as written in a Justfile or
/// Makefile: the indented lines that follow the header.
fn recipe_body(text: &str, name: &str) -> Option<String> {
    let header = format!("{name}:");
    let mut lines = text.lines();
    lines.find(|line| !line.starts_with([' ', '\t']) && line.trim_end().starts_with(&header))?;
    let mut body = String::new();
    for line in lines {
        if !line.trim().is_empty() && !line.starts_with([' ', '\t']) {
            break;
        }
        body.push_str(line);
        body.push('\n');
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

/// Provider-correct repair instruction for "CI does not run the audit lane".
/// A forge-gated repository is never told to add a workflow file the forge
/// would not execute.
pub fn audit_lane_fix(files: &[FileInfo]) -> String {
    match detect(files).primary() {
        CiProvider::GithubActions => "add a CI job that runs `jankurai audit . --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md` and uploads both artifacts".into(),
        CiProvider::Jeryu => format!(
            "add the audit to the lane your forge runs and declare it in `{JERYU_PRIMARY_DECLARATION_PATH}`: the lane command must really run `jankurai audit . --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md`"
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
            "agent/ci.toml",
            "provider = \"jeryu\"\n\n[[lane]]\nname = \"required\"\ncommand = \"just required\"\nruns = [\"jankurai audit\", \"gitleaks\"]\n",
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
                "agent/ci.toml",
                "provider = \"github-actions\"\n\n[[lane]]\nname = \"required\"\ncommand = \"just required\"\n",
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
        assert_eq!(audit_lane_anchor_path(&files), "agent/ci.toml");
        assert!(audit_lane_fix(&files).contains("agent/ci.toml"));
        assert!(!audit_lane_fix(&files).contains(".github/workflows"));
    }

    #[test]
    fn rendered_declaration_is_detected_by_the_detector() {
        let rendered = jeryu_declaration_template("required", "just required", &["jankurai audit"]);
        let files = vec![
            file("agent/ci.toml", &rendered),
            file("Justfile", "required:\n    jankurai audit .\n"),
        ];
        let surface = detect(&files);
        assert!(surface.has(CiProvider::Jeryu));
        assert_eq!(surface.lanes[0].verified_tools, vec!["jankurai audit"]);
    }
}
