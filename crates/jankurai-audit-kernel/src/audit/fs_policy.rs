use crate::model::FileInfo;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::path::Path;

const DEFAULT_MAX_CAPTURE_CHARS: usize = 120_000;
const DEFAULT_EXCLUDED_PATHS: &[&str] = &["tips/"];

#[derive(Debug, Clone)]
pub struct InventoryOptions {
    pub text_capture_chars: usize,
    pub excluded_paths: Vec<String>,
    pub extra_excluded_globs: Option<GlobSet>,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        Self {
            text_capture_chars: DEFAULT_MAX_CAPTURE_CHARS,
            excluded_paths: normalize_excluded_paths(DEFAULT_EXCLUDED_PATHS.iter().copied()),
            extra_excluded_globs: None,
        }
    }
}

impl InventoryOptions {
    pub fn from_policy(root: &Path) -> Self {
        #[derive(Debug, Deserialize, Default)]
        struct AuditPolicyFile {
            #[serde(default)]
            scan: ScanPolicy,
        }

        #[derive(Debug, Deserialize, Default)]
        struct ScanPolicy {
            text_capture_chars: Option<usize>,
            max_capture_chars: Option<usize>,
            #[serde(default)]
            excluded_paths: Vec<String>,
            #[serde(default)]
            extra_excluded_paths: Vec<String>,
            #[serde(default)]
            extra_excluded_globs: Vec<String>,
        }

        let parsed = std::fs::read_to_string(root.join("agent/audit-policy.toml"))
            .ok()
            .and_then(|text| toml::from_str::<AuditPolicyFile>(&text).ok())
            .unwrap_or_default();
        let scan = parsed.scan;
        let mut options = Self {
            text_capture_chars: scan
                .text_capture_chars
                .or(scan.max_capture_chars)
                .unwrap_or(DEFAULT_MAX_CAPTURE_CHARS),
            excluded_paths: normalize_excluded_paths(
                DEFAULT_EXCLUDED_PATHS
                    .iter()
                    .copied()
                    .map(str::to_string)
                    .chain(scan.excluded_paths)
                    .chain(scan.extra_excluded_paths),
            ),
            extra_excluded_globs: build_globset(&scan.extra_excluded_globs),
        };
        if options.text_capture_chars == 0 {
            options.text_capture_chars = DEFAULT_MAX_CAPTURE_CHARS;
        }
        options
    }
}

/// Opt-in dead-language term allowlist from `agent/audit-policy.toml`.
///
/// A repository may declare load-bearing API / protocol / domain words that the
/// HLT-001 future-hostile heuristic would otherwise flag — e.g. the HTML
/// `placeholder` attribute, the React `fallback` prop, or GitHub's `stale`
/// CheckConclusion wire value. Listing a term here suppresses ONLY that exact
/// word for the dead-marker check; every other dead-language, fallback-soup, and
/// security check still runs on the same files. A missing/empty section means
/// default behaviour, so repositories that do not opt in are unaffected.
///
/// ```toml
/// [dead_language]
/// allow_terms = ["placeholder", "fallback", "stale", "old"]
/// ```
pub fn dead_language_allow_terms(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("agent/audit-policy.toml"))
        .ok()
        .map(|text| parse_dead_language_allow_terms(&text))
        .unwrap_or_default()
}

fn parse_dead_language_allow_terms(text: &str) -> Vec<String> {
    #[derive(Debug, Deserialize, Default)]
    struct PolicyFile {
        #[serde(default)]
        dead_language: DeadLanguagePolicy,
    }
    #[derive(Debug, Deserialize, Default)]
    struct DeadLanguagePolicy {
        #[serde(default)]
        allow_terms: Vec<String>,
    }
    toml::from_str::<PolicyFile>(text)
        .ok()
        .map(|parsed| {
            parsed
                .dead_language
                .allow_terms
                .into_iter()
                .map(|term| term.trim().to_ascii_lowercase())
                .filter(|term| !term.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_excluded_paths<I, S>(paths: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = paths
        .into_iter()
        .map(|path| {
            path.as_ref()
                .trim()
                .trim_start_matches("./")
                .trim_end_matches('/')
                .to_string()
        })
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn build_globset(globs: &[String]) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut added = false;
    for glob in globs {
        let glob = glob.trim();
        if glob.is_empty() {
            continue;
        }
        if let Ok(glob) = Glob::new(glob) {
            builder.add(glob);
            added = true;
        }
    }
    if added {
        builder.build().ok()
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct InventoryResult {
    pub files: Vec<FileInfo>,
    pub timings: InventoryTimings,
}

#[derive(Debug, Clone, Default)]
pub struct InventoryTimings {
    pub walk_ms: u128,
    pub metadata_ms: u128,
    pub text_capture_ms: u128,
}

#[cfg(test)]
mod dead_language_allow_tests {
    use super::parse_dead_language_allow_terms;

    #[test]
    fn absent_section_yields_empty_allowlist() {
        // No opt-in -> default behaviour (other repos unaffected).
        assert!(parse_dead_language_allow_terms("[scan]\nexcluded_paths = []\n").is_empty());
        assert!(parse_dead_language_allow_terms("").is_empty());
    }

    #[test]
    fn parses_and_normalizes_declared_terms() {
        let terms = parse_dead_language_allow_terms(
            "[dead_language]\nallow_terms = [\"Placeholder\", \" fallback \", \"STALE\", \"\"]\n",
        );
        assert_eq!(terms, vec!["placeholder", "fallback", "stale"]);
    }

    #[test]
    fn malformed_policy_is_safe_default() {
        // A broken policy must never panic or silently disable the rule globally.
        assert!(parse_dead_language_allow_terms("not = valid = toml =").is_empty());
    }
}

/// Migrations already applied to a live database: one entry per migrations directory, naming
/// the last applied file. Files in that directory that sort at or before it are frozen —
/// editing them would break the migration tool's checksums — so migration-safety rules judge
/// only migrations added after it. Statement checks that apply to any SQL still run.
///
/// ```toml
/// [sql_migrations]
/// applied_through = ["migrations/0067_prediction_readiness.sql"]
/// ```
pub fn applied_migrations_through(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("agent/audit-policy.toml"))
        .ok()
        .map(|text| parse_applied_migrations_through(&text))
        .unwrap_or_default()
}

fn parse_applied_migrations_through(text: &str) -> Vec<String> {
    #[derive(Debug, Deserialize, Default)]
    struct PolicyFile {
        #[serde(default)]
        sql_migrations: SqlMigrationsPolicy,
    }
    #[derive(Debug, Deserialize, Default)]
    struct SqlMigrationsPolicy {
        #[serde(default)]
        applied_through: Vec<String>,
    }
    toml::from_str::<PolicyFile>(text)
        .ok()
        .map(|parsed| {
            parsed
                .sql_migrations
                .applied_through
                .into_iter()
                .map(|path| path.trim().trim_start_matches("./").to_string())
                .filter(|path| !path.is_empty() && path.contains('/'))
                .collect()
        })
        .unwrap_or_default()
}

/// True when `rel_path` is a migration at or before an `applied_through` entry in its directory.
pub fn migration_is_applied(rel_path: &str, applied_through: &[String]) -> bool {
    let (dir, name) = match rel_path.rsplit_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    applied_through.iter().any(|last| {
        last.rsplit_once('/')
            .map(|(last_dir, last_name)| last_dir == dir && name <= last_name)
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod applied_migration_tests {
    use super::*;

    #[test]
    fn applied_through_freezes_only_earlier_files_in_the_same_directory() {
        let policy = parse_applied_migrations_through(
            "[sql_migrations]\napplied_through = [\"migrations/0067_readiness.sql\"]\n",
        );
        assert!(migration_is_applied(
            "migrations/0002_datasets.sql",
            &policy
        ));
        assert!(migration_is_applied(
            "migrations/0067_readiness.sql",
            &policy
        ));
        assert!(!migration_is_applied("migrations/0068_next.sql", &policy));
        assert!(!migration_is_applied(
            "db/migrations/0002_datasets.sql",
            &policy
        ));
        assert!(parse_applied_migrations_through(
            "[sql_migrations]\napplied_through = [\"nodir.sql\"]\n"
        )
        .is_empty());
    }
}

/// Whether the reference folder layout (`profile_structure`) is enforced; default true.
///
/// ```toml
/// [reference_profile]
/// enforce = false
/// ```
pub fn reference_profile_enforced(root: &Path) -> bool {
    std::fs::read_to_string(root.join("agent/audit-policy.toml"))
        .ok()
        .map(|text| parse_reference_profile_enforced(&text))
        .unwrap_or(true)
}

fn parse_reference_profile_enforced(text: &str) -> bool {
    #[derive(Debug, Deserialize, Default)]
    struct PolicyFile {
        #[serde(default)]
        reference_profile: Option<ReferenceProfilePolicy>,
    }
    #[derive(Debug, Deserialize)]
    struct ReferenceProfilePolicy {
        #[serde(default = "enforce_default")]
        enforce: bool,
    }
    fn enforce_default() -> bool {
        true
    }
    toml::from_str::<PolicyFile>(text)
        .ok()
        .and_then(|parsed| parsed.reference_profile)
        .map(|policy| policy.enforce)
        .unwrap_or(true)
}

#[cfg(test)]
mod reference_profile_tests {
    use super::*;

    #[test]
    fn reference_profile_is_enforced_unless_a_repository_opts_out() {
        assert!(parse_reference_profile_enforced(""));
        assert!(parse_reference_profile_enforced("[reference_profile]\n"));
        assert!(!parse_reference_profile_enforced(
            "[reference_profile]\nenforce = false\n"
        ));
    }
}
