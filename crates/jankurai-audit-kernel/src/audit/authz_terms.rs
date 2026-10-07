//! Identifier-boundary matching for `HLT-022-AUTHZ-ISOLATION-GAP`.
//!
//! The detector looks for authorization and data-isolation surfaces such as
//! `owner_id`, `tenant_id`, `org_id`, `rls` or `admin`. A plain substring match
//! read `rls` inside `urls` and `cdpUrlSetting`, so this module matches the
//! terms as whole identifier tokens instead.
//!
//! A line is split into tokens on every non-alphanumeric character
//! (snake_case, kebab-case, dotted paths, spaces, punctuation) and inside each
//! word at camelCase boundaries:
//!
//! - lower to upper: `cdpUrlSetting` -> `cdp`, `Url`, `Setting`;
//! - letter to digit and digit to letter: `org2id` -> `org`, `2`, `id`;
//! - acronym to word: an upper-case run followed by an upper-case letter and
//!   at least two lower-case letters splits before that letter, so
//!   `RLSPolicy` -> `RLS`, `Policy` and `HTMLParser` -> `HTML`, `Parser`.
//!
//! An all-caps run stays one token. `RLS` and `ENABLE_RLS` therefore match
//! `rls`, while `IRLS` is its own acronym and does not. A single trailing
//! lower-case letter stays with the acronym before it, so `URLs` and `IDs` are
//! the tokens `urls` and `ids`, not `ur` + `ls`.
//!
//! Tokens compare case-insensitively. A term token also matches its plural
//! (`owner_ids`, `admins`). Multi-word terms match consecutive tokens, so
//! `owner_id`, `ownerId`, `OWNER-ID` and `record.owner_id` all match
//! `owner_id`, and `ROW LEVEL SECURITY` matches `row level security`.
//! `admin` also matches `administrator` and `superadmin`.
//!
//! A SQL `CREATE POLICY` statement whose `USING (` or `WITH CHECK (` clause is
//! on the same line or the next three lines is reported as `create policy`.
//!
//! A line within two lines of a `jankurai:allow HLT-022-AUTHZ-ISOLATION-GAP`
//! comment with `reason=` and `expires=` is skipped, as for HLT-023.

use super::language_rules::common::nearby_allow;
use super::scan::AUTHZ_ISOLATION_PATTERNS;
use once_cell::sync::Lazy;
use regex::Regex;

const AUTHZ_RULE_ID: &str = "HLT-022-AUTHZ-ISOLATION-GAP";

/// Extra whole-token spellings of the `admin` term.
const ADMIN_ALIASES: &[&str] = &["administrator", "superadmin"];

/// The label reported for a matched SQL row-security policy.
pub const CREATE_POLICY_TERM: &str = "create policy";

static POLICY_CLAUSE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(using|with\s+check)\s*\(").expect("valid policy clause regex")
});

/// Split `text` into lower-cased identifier tokens (see the module docs).
pub fn identifier_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        split_word(word, &mut tokens);
    }
    tokens
}

fn split_word(word: &str, out: &mut Vec<String>) {
    let chars: Vec<char> = word.chars().collect();
    let mut start = 0;
    for i in 1..chars.len() {
        let (prev, cur) = (chars[i - 1], chars[i]);
        let lower_to_upper = prev.is_ascii_lowercase() && cur.is_ascii_uppercase();
        let digit_edge = prev.is_ascii_digit() != cur.is_ascii_digit();
        let acronym_to_word = prev.is_ascii_uppercase()
            && cur.is_ascii_uppercase()
            && chars[i + 1..]
                .iter()
                .take_while(|c| c.is_ascii_lowercase())
                .count()
                >= 2;
        if lower_to_upper || digit_edge || acronym_to_word {
            out.push(
                chars[start..i]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase(),
            );
            start = i;
        }
    }
    if start < chars.len() {
        out.push(
            chars[start..]
                .iter()
                .collect::<String>()
                .to_ascii_lowercase(),
        );
    }
}

fn token_matches(term: &str, token: &str) -> bool {
    token == term
        || token.strip_suffix('s') == Some(term)
        || (term == "admin"
            && ADMIN_ALIASES
                .iter()
                .any(|alias| token == *alias || token.strip_suffix('s') == Some(*alias)))
}

fn contains_term(tokens: &[String], term: &[String]) -> bool {
    !term.is_empty()
        && tokens.windows(term.len()).any(|window| {
            window
                .iter()
                .zip(term)
                .all(|(token, part)| token_matches(part, token))
        })
}

/// The first authz/isolation term on `line`, in `AUTHZ_ISOLATION_PATTERNS` order.
pub fn matched_term(line: &str) -> Option<&'static str> {
    let tokens = identifier_tokens(line);
    AUTHZ_ISOLATION_PATTERNS
        .iter()
        .copied()
        .find(|pattern| contains_term(&tokens, &identifier_tokens(pattern)))
}

fn is_create_policy(lines: &[&str], idx: usize) -> bool {
    let tokens = identifier_tokens(lines[idx]);
    let create_policy = ["create".to_string(), "policy".to_string()];
    tokens.windows(2).any(|w| w == create_policy)
        && lines[idx..(idx + 4).min(lines.len())]
            .iter()
            .any(|line| POLICY_CLAUSE_RE.is_match(line))
}

/// The first non-allowed surface line in `text`: its 1-based line number and term.
pub fn first_surface_line(text: &str) -> Option<(usize, &'static str)> {
    let lines: Vec<&str> = text.lines().collect();
    (0..lines.len()).find_map(|idx| {
        let term = matched_term(lines[idx])
            .or_else(|| is_create_policy(&lines, idx).then_some(CREATE_POLICY_TERM))?;
        (!nearby_allow(text, idx + 1, AUTHZ_RULE_ID)).then_some((idx + 1, term))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(line: &str) -> Option<&'static str> {
        first_surface_line(line).map(|(_, term)| term)
    }

    #[test]
    fn tokens_split_snake_camel_kebab_dotted_and_acronyms() {
        assert_eq!(
            identifier_tokens("record.owner_id cdpUrlSetting row-level RLSPolicy URLs IRLS org2id"),
            [
                "record", "owner", "id", "cdp", "url", "setting", "row", "level", "rls", "policy",
                "urls", "irls", "org", "2", "id"
            ]
        );
    }

    #[test]
    fn rls_true_positives_still_match() {
        assert_eq!(term("alter table t enable_rls();"), Some("rls"));
        assert_eq!(term("const RLS = true;"), Some("rls"));
        assert_eq!(term("let rls_enabled = check_rls(conn);"), Some("rls"));
        assert_eq!(
            term("ALTER TABLE notes ENABLE ROW LEVEL SECURITY;"),
            Some("row level security")
        );
        assert_eq!(
            term("fn row_level_security() {}"),
            Some("row level security")
        );
    }

    #[test]
    fn sql_create_policy_with_using_clause_matches() {
        let sql =
            "CREATE POLICY notes_owner ON notes\n  FOR SELECT\n  USING (author = current_user);\n";
        assert_eq!(first_surface_line(sql), Some((1, CREATE_POLICY_TERM)));
        assert_eq!(
            term("create policy p on t with check (true);"),
            Some(CREATE_POLICY_TERM)
        );
        assert_eq!(term("// TODO: create policy docs"), None);
    }

    #[test]
    fn rls_inside_other_words_does_not_match() {
        assert_eq!(term("const checked_cdp_urls = [];"), None);
        assert_eq!(term("const cdpUrlSetting = settings.cdpUrl;"), None);
        assert_eq!(term("for (const url of URLs) {}"), None);
        assert_eq!(term("IRLS index refresh"), None);
        assert_eq!(term("let curls = girls + whirls;"), None);
    }

    #[test]
    fn owner_tenant_org_ids_match_across_naming_styles() {
        assert_eq!(term("where tenant_id = $1"), Some("tenant_id"));
        assert_eq!(
            term("db.filter({ tenantId: session.tenantId })"),
            Some("tenant_id")
        );
        assert_eq!(term("WHERE OWNER_ID = ?"), Some("owner_id"));
        assert_eq!(term("let ids = owner_ids(rows);"), Some("owner_id"));
        assert_eq!(term("headers['x-org-id']"), Some("org_id"));
        assert_eq!(term("user.organizationId"), Some("organization_id"));
        assert_eq!(term("let ownerless = idle;"), None);
        assert_eq!(term("let tenantidx = 0;"), None);
        assert_eq!(term("fn borg_id() {}"), None);
    }

    #[test]
    fn admin_matches_identifiers_not_substrings() {
        assert_eq!(term("if (user.isAdmin) {"), Some("admin"));
        assert_eq!(term("require_admin(&session)?;"), Some("admin"));
        assert_eq!(term("const ADMINS = load();"), Some("admin"));
        assert_eq!(term("if is_administrator(user) {"), Some("admin"));
        assert_eq!(term("role === 'superadmin'"), Some("admin"));
        assert_eq!(term("const badminton = 1;"), None);
        assert_eq!(term("adminer_port = 8080"), None);
    }

    #[test]
    fn allow_comment_skips_only_the_nearby_line() {
        let text =
            "// jankurai:allow HLT-022-AUTHZ-ISOLATION-GAP reason=label text expires=2099-12-31\n\
                    const adminLabel = 'Admin';\n\
                    x();\n\
                    y();\n\
                    z();\n\
                    if (user.isAdmin) {}\n";
        assert_eq!(first_surface_line(text), Some((6, "admin")));
        let unexpired =
            "// jankurai:allow HLT-022-AUTHZ-ISOLATION-GAP reason=label text\nconst admin = 1;\n";
        assert_eq!(first_surface_line(unexpired), Some((2, "admin")));
    }
}
