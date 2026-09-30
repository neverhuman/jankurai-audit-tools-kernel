use crate::audit::ci_provider;
use crate::model::FileInfo;
use serde_json::Value as JsonValue;

pub fn operational_command_text(files: &[FileInfo]) -> String {
    operational_command_lines(files).join("\n")
}

pub fn operational_command_lines(files: &[FileInfo]) -> Vec<String> {
    let mut lines = Vec::new();
    for file in files {
        match file.name.as_str() {
            "Justfile" | "justfile" | "Makefile" | "makefile" => {
                lines.extend(shell_lines(&file.text));
            }
            "package.json" => {
                lines.extend(package_scripts(&file.text));
            }
            "Taskfile.yml" | "Taskfile.yaml" | "taskfile.yml" | "taskfile.yaml" => {
                lines.extend(shell_lines(&file.text));
            }
            _ if ci_provider::is_github_workflow_yaml_path(&file.rel_path) => {
                lines.extend(ci_provider::github_workflow_commands(&file.text));
            }
            _ => {}
        }
    }
    // Lanes a forge runs are not committed as workflow files, so they are not
    // reached by the per-file match above.
    lines.extend(ci_provider::jeryu_lane_command_lines(files));
    lines
}

fn package_scripts(text: &str) -> Vec<String> {
    let parsed = match serde_json::from_str::<JsonValue>(text) {
        Ok(parsed) => parsed,
        Err(_) => return vec![],
    };
    parsed
        .get("scripts")
        .and_then(|scripts| scripts.as_object())
        .into_iter()
        .flat_map(|scripts| scripts.values())
        .filter_map(|value| value.as_str())
        .flat_map(shell_lines)
        .collect()
}

fn shell_lines(text: &str) -> Vec<String> {
    ci_provider::shell_lines(text)
}
