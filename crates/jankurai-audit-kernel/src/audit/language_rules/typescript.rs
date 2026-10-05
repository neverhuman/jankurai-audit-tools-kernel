use super::catalog::{
    ConfidencePolicy, Language, LanguageFinding, LanguageRule, Matcher, ProofWindow,
};
use crate::audit::helpers::AuditContext;
use crate::audit::scan;
use crate::model::FileInfo;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

const HLT_RULE_ID: &str = "HLT-031-TYPESCRIPT-BAD-BEHAVIOR";

const HARD_RULES: &[LanguageRule] = &[
    LanguageRule {
        id: "typescript.suppress.ts-nocheck",
        language: Language::TypeScript,
        hlt_rule_id: HLT_RULE_ID,
        severity: "high",
        category: "boundary",
        lane: "fast",
        confidence: ConfidencePolicy::High,
        matcher: Matcher::ContainsAny(&["@ts-nocheck", "@ts-ignore", "eslint-disable"]),
        proof_window: ProofWindow::None,
        problem: "TypeScript suppression comment hides type checking or lint evidence",
        fix: "remove the broad suppression or scope it to a single justified line",
    },
    LanguageRule {
        id: "typescript.types.any-boundary",
        language: Language::TypeScript,
        hlt_rule_id: HLT_RULE_ID,
        severity: "high",
        category: "boundary",
        lane: "fast",
        confidence: ConfidencePolicy::High,
        matcher: Matcher::ContainsAny(&[
            "as any",
            "as unknown as",
            "json.parse(",
            "response.json(",
            "req.body",
        ]),
        proof_window: ProofWindow::None,
        problem: "unchecked boundary cast or parse result crosses a trust boundary",
        fix: "validate the value first, then narrow it with a proof-aware decoder",
    },
    LanguageRule {
        id: "typescript.config.strict-disabled",
        language: Language::TypeScript,
        hlt_rule_id: HLT_RULE_ID,
        severity: "high",
        category: "boundary",
        lane: "fast",
        confidence: ConfidencePolicy::High,
        matcher: Matcher::ContainsAny(&[
            "\"strict\": false",
            "\"strictnullchecks\": false",
            "\"noemitonerror\": false",
        ]),
        proof_window: ProofWindow::None,
        problem: "TypeScript compiler strictness is disabled in a repo config file",
        fix: "restore strict compiler settings and narrow the exception to a local test fixture",
    },
    LanguageRule {
        id: "typescript.runtime.dangerous-eval-dom",
        language: Language::TypeScript,
        hlt_rule_id: HLT_RULE_ID,
        severity: "high",
        category: "security",
        lane: "fast",
        confidence: ConfidencePolicy::High,
        matcher: Matcher::ContainsAny(&[
            "eval(",
            "new function(",
            "dangerouslysetinnerhtml",
            ".innerhtml =",
            "innerhtml =",
        ]),
        proof_window: ProofWindow::None,
        problem: "dynamic code or raw HTML sink appears in product TypeScript",
        fix: "replace the dynamic sink with a bounded parser, sanitizer, or typed renderer",
    },
    LanguageRule {
        id: "typescript.security.raw-command-sql",
        language: Language::TypeScript,
        hlt_rule_id: HLT_RULE_ID,
        severity: "high",
        category: "security",
        lane: "fast",
        confidence: ConfidencePolicy::High,
        matcher: Matcher::ContainsAny(&["exec(", "spawn(", ".query(", ".execute(", ".raw("]),
        proof_window: ProofWindow::None,
        problem: "raw shell or SQL text is built from untrusted TypeScript input",
        fix: "use argv arrays, prepared statements, or a safe allowlisted command path",
    },
];

pub fn catalog() -> &'static [LanguageRule] {
    HARD_RULES
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeScriptSummary {
    pub hard_findings: usize,
    pub advisory_signals: usize,
}

pub fn summary(ctx: &AuditContext) -> TypeScriptSummary {
    TypeScriptSummary {
        hard_findings: findings(ctx).len(),
        advisory_signals: advisory_signals(ctx).len(),
    }
}

pub fn findings(ctx: &AuditContext) -> Vec<LanguageFinding> {
    sort_and_cap_findings(hard_findings(ctx), 50)
}

pub fn advisory_signals(ctx: &AuditContext) -> Vec<LanguageFinding> {
    sort_and_cap_findings(advisory_hits(ctx), 50)
}

fn hard_findings(ctx: &AuditContext) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for file in typescript_files(ctx) {
        if is_ts_config(file) {
            out.extend(tsconfig_hard_hits(file));
            continue;
        }
        out.extend(ts_source_hard_hits(file));
    }
    out
}

fn advisory_hits(ctx: &AuditContext) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for file in typescript_files(ctx) {
        if is_ts_config(file) {
            out.extend(tsconfig_advisory_hits(file));
            continue;
        }
        out.extend(ts_source_advisory_hits(file));
    }
    out
}

fn typescript_files(ctx: &AuditContext) -> Vec<&FileInfo> {
    let zone_paths = crate::audit::helpers::generated_zone_suppression_paths(ctx);
    ctx.all_files
        .iter()
        .filter(|file| is_typescript_surface(file, &zone_paths))
        .collect()
}

fn is_typescript_surface(file: &FileInfo, generated_zone_paths: &[String]) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    if scan::is_generated_or_reference_path(&file.rel_path)
        || scan::is_test_or_example_path(&file.rel_path)
        || lower.starts_with("fixtures/")
        || lower.contains("/fixtures/")
    {
        return false;
    }
    if generated_zone_paths
        .iter()
        .any(|zone| crate::audit::helpers::path_matches_prefix(&file.rel_path, zone))
    {
        return false;
    }
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
        || is_ts_config(file)
}

fn is_ts_config(file: &FileInfo) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    lower.ends_with("tsconfig.json") || lower.starts_with("tsconfig.") && lower.ends_with(".json")
}

fn ts_source_hard_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    let code_only = typescript_code_lines(&file.text);
    for (idx, line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        let lower = line.to_ascii_lowercase();
        let code_lower = code_only[idx].to_ascii_lowercase();
        if lower.contains("@ts-nocheck")
            || lower.contains("@ts-ignore")
            || lower.contains("eslint-disable")
        {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.suppress.ts-nocheck",
                file,
                line_no,
                "TypeScript suppression comment hides type checking or lint evidence",
                "broad suppression is hard to audit",
                "remove the broad suppression or scope it to a single justified line",
            ));
        }
        if casts_at_trust_boundary(&code_lower) {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.types.any-boundary",
                file,
                line_no,
                "unchecked boundary cast or parse result crosses a trust boundary",
                "value shape is not proven before the cast",
                "validate the value first, then narrow it with a proof-aware decoder",
            ));
        }
        if dangerous_eval_or_html(&lower) {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.runtime.dangerous-eval-dom",
                file,
                line_no,
                "dynamic code or raw HTML sink appears in product TypeScript",
                "sink is not proven safe locally",
                "replace the dynamic sink with a bounded parser, sanitizer, or typed renderer",
            ));
        }
        if raw_shell_or_sql(&lower) {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.security.raw-command-sql",
                file,
                line_no,
                "raw shell or SQL text is built from untrusted TypeScript input",
                "trusted input proof is missing",
                "use argv arrays, prepared statements, or a safe allowlisted command path",
            ));
        }
    }
    // Honor inline reasoned allow annotations (`jankurai:allow <detector>
    // reason=... expires=YYYY-MM-DD`), consistent with the web-security and
    // input-boundary detectors: a reviewed, time-bounded exception at a
    // provably-safe sink (e.g. DOMPurify-sanitized Markdown rendered via
    // `dangerouslySetInnerHTML`) is suppressed. Empty/absent annotation =
    // default behaviour, so repositories that do not annotate are unaffected.
    out.retain(|f| !super::common::nearby_allow(&file.text, f.line.unwrap_or(0), f.matched_term));
    out
}

fn tsconfig_hard_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    if let Ok(parsed) = serde_json::from_str::<JsonValue>(&file.text) {
        if let Some(options) = parsed.get("compilerOptions").and_then(JsonValue::as_object) {
            for (key, detector_id, _matched_term, problem, reason, fix) in [
                (
                    "strict",
                    "typescript.config.strict-disabled",
                    "strict",
                    "TypeScript compiler strictness is disabled in a repo config file",
                    "strict mode is explicitly off",
                    "restore strict compiler settings and narrow the exception to a local test fixture",
                ),
                (
                    "strictNullChecks",
                    "typescript.config.strict-disabled",
                    "strictNullChecks",
                    "TypeScript compiler strictness is disabled in a repo config file",
                    "nullability discipline is explicitly off",
                    "restore strict compiler settings and narrow the exception to a local test fixture",
                ),
                (
                    "noEmitOnError",
                    "typescript.config.strict-disabled",
                    "noEmitOnError",
                    "TypeScript compiler strictness is disabled in a repo config file",
                    "compiler emits on errors",
                    "restore strict compiler settings and narrow the exception to a local test fixture",
                ),
            ] {
                if options.get(key).and_then(JsonValue::as_bool) == Some(false) {
                    if let Some(line_no) = json_key_line(&file.text, key, false) {
                        out.push(finding(
                            HLT_RULE_ID,
                            detector_id,
                            file,
                            line_no,
                            problem,
                            reason,
                            fix,
                        ));
                    }
                }
            }
        }
    } else {
        for (idx, line) in file.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("\"strict\": false")
                || lower.contains("\"strictnullchecks\": false")
                || lower.contains("\"noemitonerror\": false")
            {
                out.push(finding(
                    HLT_RULE_ID,
                    "typescript.config.strict-disabled",
                    file,
                    idx + 1,
                    "TypeScript compiler strictness is disabled in a repo config file",
                    "strict compiler settings are off",
                    "restore strict compiler settings and narrow the exception to a local test fixture",
                ));
            }
        }
    }
    out
}

fn ts_source_advisory_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for (idx, line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        let lower = line.to_ascii_lowercase();
        if NON_NULL_ASSERTION_RE.is_match(line) {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.review.non-null-assertion",
                file,
                line_no,
                "non-null assertion deserves a proof check",
                "nullability proof is review-worthy",
                "prefer an explicit guard or a decoded value instead of a non-null assertion",
            ));
        }
        if lower.contains("partial<") {
            out.push(finding(
                HLT_RULE_ID,
                "typescript.review.partial-patch",
                file,
                line_no,
                "Partial<T> patch shape deserves a proof check",
                "patch semantics are review-worthy",
                "model the patch shape explicitly or validate the object before merging it",
            ));
        }
    }
    out
}

fn tsconfig_advisory_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    if let Ok(parsed) = serde_json::from_str::<JsonValue>(&file.text) {
        if let Some(options) = parsed.get("compilerOptions").and_then(JsonValue::as_object) {
            if options.get("skipLibCheck").and_then(JsonValue::as_bool) == Some(true) {
                if let Some(line_no) = json_key_line(&file.text, "skipLibCheck", true) {
                    out.push(finding(
                        HLT_RULE_ID,
                        "typescript.review.skip-lib-check",
                        file,
                        line_no,
                        "skipLibCheck is enabled in a repo config file",
                        "library type checking is review-worthy",
                        "remove the override or justify it in a local test-only config",
                    ));
                }
            }
        }
    }
    out
}

/// Strip comments and string/template literal contents from TypeScript source so
/// prose cannot be read as code. Returns one entry per input line, in order, with
/// block comments (including JSDoc continuation lines) tracked across lines.
///
/// String literals collapse to a single `0` placeholder: the token still exists for
/// `"text" as Foo`, but its contents can no longer match a marker.
fn typescript_code_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block_comment = false;

    for raw_line in text.lines() {
        let mut code = String::with_capacity(raw_line.len());
        let mut chars = raw_line.chars().peekable();

        while let Some(ch) = chars.next() {
            if in_block_comment {
                if ch == '*' && matches!(chars.peek(), Some(&'/')) {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            if ch == '/' {
                match chars.peek() {
                    Some(&'/') => break,
                    Some(&'*') => {
                        chars.next();
                        in_block_comment = true;
                        continue;
                    }
                    _ => {}
                }
            }
            if ch == '"' || ch == '\'' || ch == '`' {
                let quote = ch;
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if inner == '\\' {
                        escaped = true;
                        continue;
                    }
                    if inner == quote {
                        break;
                    }
                }
                code.push('0');
                continue;
            }
            code.push(ch);
        }

        out.push(code.trim().to_string());
    }

    out
}

/// A real TS `as` expression: an expression token, ` as `, then a type token.
static AS_CAST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9_$)\]]\s+as\s+(?:const\b|[A-Za-z_$(\[{])")
        .expect("TypeScript as-cast regex is valid")
});

/// Boundary markers as identifiers, so `<input>` in JSX and a word like `inputs`
/// in prose do not count. A leading `.` is allowed (`req.params`).
static BOUNDARY_MARKER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:^|[^<\w$-])(?:req\.body|request\.body|response\.json\s*\(|fetch\s*\(|json\.parse\s*\(|process\.env|params|query|input)\b",
    )
    .expect("TypeScript boundary marker regex is valid")
});

/// `import { x as y }`, `export * as ns from ...`: an alias, not a cast.
fn is_import_export_alias(code_lower: &str) -> bool {
    (code_lower.starts_with("import ")
        || code_lower.starts_with("import{")
        || code_lower.starts_with("export ")
        || code_lower.starts_with("export{"))
        && !code_lower.contains('=')
}

/// `code_lower` must be a lowercased, comment- and string-stripped source line.
fn casts_at_trust_boundary(code_lower: &str) -> bool {
    if code_lower.is_empty() || is_import_export_alias(code_lower) {
        return false;
    }
    let cast = code_lower.contains(" as any")
        || code_lower.contains(" as unknown as")
        || AS_CAST_RE.is_match(code_lower);
    cast && BOUNDARY_MARKER_RE.is_match(code_lower)
}

fn dangerous_eval_or_html(lower: &str) -> bool {
    if lower.contains("dangerouslysetinnerhtml") {
        return !lower.contains("sanitize")
            && !lower.contains("dompurify")
            && !lower.contains("trusted");
    }
    if lower.contains(".innerhtml =") || lower.contains("innerhtml =") {
        return !lower.contains("sanitize")
            && !lower.contains("dompurify")
            && !lower.contains("trusted");
    }
    lower.contains("eval(") || lower.contains("new function(")
}

fn raw_shell_or_sql(lower: &str) -> bool {
    let untrusted = [
        "req.",
        "request.",
        "body",
        "params",
        "query",
        "process.env",
        "user",
        "input",
        "command",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let interpolated = lower.contains("${") || lower.contains('+');
    let shell = lower.contains("exec(")
        || lower.contains("spawn(")
        || lower.contains("execsync(")
        || lower.contains("spawnsync(");
    let sql = lower.contains(".query(")
        || lower.contains(".execute(")
        || lower.contains(".raw(")
        || lower.contains("select ")
        || lower.contains("update ")
        || lower.contains("delete ")
        || lower.contains("insert ")
        || lower.contains("drop ");
    (shell || sql) && untrusted && interpolated
}

fn json_key_line(text: &str, key: &str, value: bool) -> Option<usize> {
    let needle = format!("\"{key}\": {value}");
    let lower_needle = needle.to_ascii_lowercase();
    text.lines().enumerate().find_map(|(idx, line)| {
        if line.to_ascii_lowercase().contains(&lower_needle) {
            Some(idx + 1)
        } else {
            None
        }
    })
}

fn sort_and_cap_findings(mut findings: Vec<LanguageFinding>, max: usize) -> Vec<LanguageFinding> {
    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.unwrap_or(0).cmp(&b.line.unwrap_or(0)))
            .then(a.rule_id.cmp(b.rule_id))
            .then(a.matched_term.cmp(b.matched_term))
    });
    let mut seen = BTreeSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            let key = (
                finding.rule_id.to_string(),
                finding.path.clone(),
                finding.line.unwrap_or(0),
                finding.matched_term.to_string(),
            );
            seen.insert(key)
        })
        .take(max)
        .collect()
}

fn finding(
    rule_id: &'static str,
    detector_id: &'static str,
    file: &FileInfo,
    line_no: usize,
    problem: &str,
    reason: &str,
    fix: &str,
) -> LanguageFinding {
    let snippet = file
        .text
        .lines()
        .nth(line_no.saturating_sub(1))
        .map(|line| line.trim().chars().take(160).collect::<String>())
        .unwrap_or_default();
    LanguageFinding::new(
        rule_id,
        detector_id,
        file.rel_path.clone(),
        Some(line_no),
        snippet.clone(),
        problem,
        reason,
        fix,
        vec![
            format!("detector={detector_id}"),
            format!("path={}", file.rel_path),
            format!("line={line_no}"),
            format!("snippet={snippet}"),
        ],
    )
}

static NON_NULL_ASSERTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*!\s*(?:\.|\[|\(|;|,|\)|\}|:|$)")
        .expect("non-null assertion regex is valid")
});

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn file_info(rel_path: &str, text: &str) -> FileInfo {
        let name = std::path::Path::new(rel_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let suffix = std::path::Path::new(rel_path)
            .extension()
            .map(|ext| format!(".{}", ext.to_string_lossy()))
            .unwrap_or_default();
        FileInfo {
            rel_path: rel_path.into(),
            name,
            suffix,
            size: text.len() as u64,
            line_count: text.lines().count(),
            text: text.into(),
            is_generated: false,
            is_code: true,
        }
    }

    fn any_boundary_lines(text: &str) -> Vec<usize> {
        ts_source_hard_hits(&file_info("src/sample.ts", text))
            .into_iter()
            .filter(|finding| finding.matched_term == "typescript.types.any-boundary")
            .map(|finding| finding.line.unwrap_or(0))
            .collect()
    }

    #[test]
    fn prose_in_a_jsdoc_comment_is_not_a_cast() {
        let text = concat!(
            "/**\n",
            " * An <input type=\"datetime-local\"> value as the RFC 3339 instant the API\n",
            " * expects. Query params are parsed as the caller asked.\n",
            " */\n",
            "export function toInstant(value: string): string {\n",
            "  return value;\n",
            "}\n",
        );
        assert!(any_boundary_lines(text).is_empty(), "{text}");
    }

    #[test]
    fn line_comments_and_string_literals_are_not_casts() {
        let text = concat!(
            "// read the query value as the raw input string\n",
            "const label = \"pick a value as the query input\";\n",
            "const note = `a fetch( value as the params`;\n",
        );
        assert!(any_boundary_lines(text).is_empty(), "{text}");
    }

    #[test]
    fn import_and_export_aliases_are_not_casts() {
        let text = concat!(
            "import { query as runQuery } from \"./db\";\n",
            "import type { Params as QueryParams } from \"./types\";\n",
            "export * as input from \"./input\";\n",
        );
        assert!(any_boundary_lines(text).is_empty(), "{text}");
    }

    #[test]
    fn jsx_input_element_is_not_a_boundary_marker() {
        let text = "const field = <input value={label as string} />;\n";
        assert!(any_boundary_lines(text).is_empty(), "{text}");
    }

    #[test]
    fn real_boundary_casts_still_fire() {
        assert_eq!(
            any_boundary_lines("const parsed = JSON.parse(raw) as Foo;\n"),
            vec![1]
        );
        assert_eq!(
            any_boundary_lines("const body = req.body as any;\n"),
            vec![1]
        );
        assert_eq!(
            any_boundary_lines("const id = req.params.id as unknown as UserId;\n"),
            vec![1]
        );
        assert_eq!(
            any_boundary_lines("const data = (await fetch(url)) as ApiPayload;\n"),
            vec![1]
        );
    }

    #[test]
    fn suppression_detector_still_reads_comments() {
        let hits =
            ts_source_hard_hits(&file_info("src/sample.ts", "// eslint-disable-next-line\n"));
        assert!(hits
            .iter()
            .any(|finding| finding.matched_term == "typescript.suppress.ts-nocheck"));
    }
}
