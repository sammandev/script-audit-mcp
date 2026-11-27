use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    Engine, Result,
    bundle::{self, BundleFile, BundleReport, ValidateBundleRequest},
    devices,
    model::ValidationReport,
};

#[derive(Serialize, JsonSchema)]
pub(crate) struct LinePreview {
    original: String,
    corrected: String,
    changed: bool,
    validation: Option<ValidationReport>,
    validation_error: Option<String>,
}

pub(crate) fn line(engine: &Engine, line: &str, device_scope: Option<&str>) -> LinePreview {
    let interfaces = devices::interfaces(&engine.snapshot.functions);
    line_with_interfaces(engine, line, device_scope, &interfaces)
}

fn line_with_interfaces(
    engine: &Engine,
    line: &str,
    device_scope: Option<&str>,
    interfaces: &[(String, String)],
) -> LinePreview {
    let mut corrected = line.to_string();
    if !crate::is_commented_line(line)
        && crate::is_supported_line_width(line.split('|').count())
        && let Some((device, remainder)) = line.split_once('|')
    {
        let (base, suffix) = match device.split_once('#') {
            Some((base, mode @ ("QUICK" | "PROXY"))) => (base, Some(mode)),
            Some(_) => (device, None),
            None => (device, None),
        };
        if let Ok(matched) = devices::resolve(base, interfaces)
            && matched.matched_by == devices::MatchedBy::Interface
            && matched.script_device.starts_with("DLL")
        {
            let mode = suffix.map(|mode| format!("#{mode}")).unwrap_or_default();
            let candidate = format!("{}{mode}", matched.script_device);
            let function = remainder.split('|').next().unwrap_or_default();
            if engine.resolve_function(&candidate, function).is_ok() {
                corrected = format!("{candidate}|{remainder}");
            }
        }
    }
    let (validation, validation_error) = match engine.validate_line(&corrected, device_scope) {
        Ok(report) => (Some(report), None),
        Err(error) => (None, Some(error.to_string())),
    };
    LinePreview {
        original: line.to_string(),
        changed: corrected != line,
        corrected,
        validation,
        validation_error,
    }
}

#[derive(Serialize)]
pub(crate) struct BundleChange {
    file: String,
    line: usize,
    from: String,
    to: String,
}

#[derive(Serialize)]
pub(crate) struct BundlePreview {
    original_files: Vec<BundleFile>,
    corrected_files: Vec<BundleFile>,
    changes: Vec<BundleChange>,
    validation: BundleReport,
}

pub(crate) fn bundle(engine: &Engine, request: ValidateBundleRequest) -> Result<BundlePreview> {
    let original = bundle::validate(request.clone(), engine)?;
    let interfaces = devices::interfaces(&engine.snapshot.functions);
    let mut replacements = std::collections::BTreeMap::new();
    let mut changes = Vec::new();
    for section in &original.script_sections {
        for row in &section.rows {
            let Some((_, value)) = row.raw.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
                continue;
            }
            let payload = &value[1..value.len() - 1];
            let preview = line_with_interfaces(
                engine,
                payload,
                request.device_scope.as_deref(),
                &interfaces,
            );
            if !preview.changed {
                continue;
            }
            let Some((device, _)) = payload.split_once('|') else {
                continue;
            };
            let Some((corrected_device, _)) = preview.corrected.split_once('|') else {
                continue;
            };
            let Some(value_start) = row.raw.find('=') else {
                continue;
            };
            let Some(quote) = row.raw[value_start + 1..].find('"') else {
                continue;
            };
            let start = value_start + quote + 2;
            let mut corrected_row = row.raw.clone();
            corrected_row.replace_range(start..start + device.len(), corrected_device);
            replacements.insert((section.file.clone(), row.line), corrected_row);
            changes.push(BundleChange {
                file: section.file.clone(),
                line: row.line,
                from: device.to_string(),
                to: corrected_device.to_string(),
            });
        }
    }
    let original_files = request.files.clone();
    let mut corrected_request = request;
    for file in &mut corrected_request.files {
        let mut text = String::new();
        for (index, source_line) in file.text.split_inclusive('\n').enumerate() {
            if let Some(replacement) = replacements.get(&(file.name.clone(), index + 1)) {
                text.push_str(replacement);
                if source_line.ends_with("\r\n") {
                    text.push_str("\r\n");
                } else if source_line.ends_with('\n') {
                    text.push('\n');
                }
            } else {
                text.push_str(source_line);
            }
        }
        file.text = text;
    }
    let validation = bundle::validate(corrected_request.clone(), engine)?;
    Ok(BundlePreview {
        original_files,
        corrected_files: corrected_request.files,
        changes,
        validation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Function, Snapshot};

    #[test]
    fn builtin_device_wins_when_interface_names_collide() {
        let engine = Engine::new(Snapshot {
            functions: vec![
                Function {
                    source: "BUILT-IN".into(),
                    interface: "WIFI_TEST".into(),
                    name: "RUN".into(),
                    ..Function::default()
                },
                Function {
                    source: "DLL".into(),
                    interface: "WIFI_TEST".into(),
                    name: "RUN".into(),
                    ..Function::default()
                },
            ],
            ..Snapshot::default()
        });
        let source = "WIFI_TEST|RUN|NULL|NULL|100";
        let preview = line(&engine, source, None);
        assert_eq!(preview.corrected, source);
        assert!(!preview.changed);
    }
}
