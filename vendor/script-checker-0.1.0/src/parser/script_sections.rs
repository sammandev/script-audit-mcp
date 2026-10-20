use std::collections::HashMap;

use crate::diagnostics::{Diagnostic, Severity};
use crate::models::{DataEntry, DataSection, ScriptRow, ScriptSection};
use crate::parser::common::{
    case_key, invalid_flow_section_kind, is_error_code_format, is_ignored_line, parse_any_section,
    parse_data_assignment, parse_flow_section, parse_script_row, section_name, section_name_parts,
    split_retry_label,
};

const CORE_FUNCTION_FIELD_COUNT: usize = 7;
const MAX_FUNCTION_FIELD_COUNT: usize = 8;

#[derive(Debug, Clone)]
pub struct ParsedScriptSections {
    pub sections: Vec<ScriptSection>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParsedScriptSections {
    pub fn section_by_name(&self, name: &str) -> Option<&ScriptSection> {
        let key = case_key(name);
        self.sections
            .iter()
            .find(|section| case_key(&section.name) == key)
    }
}

pub fn parse_script_sections_text(text: &str, source_name: &str) -> ParsedScriptSections {
    let mut sections: Vec<ScriptSection> = Vec::new();
    let mut diagnostics = Vec::new();
    let mut section_index: HashMap<String, usize> = HashMap::new();
    let mut current_index: Option<usize> = None;
    let mut in_flow = false;

    for (line_index, raw) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if is_ignored_line(raw) {
            continue;
        }

        if parse_flow_section(raw).is_some() {
            current_index = None;
            in_flow = true;
            continue;
        }

        if invalid_flow_section_kind(raw).is_some() {
            current_index = None;
            in_flow = true;
            continue;
        }

        if let Some(display_name) = parse_any_section(raw) {
            let display_name = display_name.trim().to_string();
            let parts = section_name_parts(&display_name);
            let name = parts.name;
            let key = case_key(&name);
            if let Some(existing_index) = section_index.get(&key).copied() {
                let first_line = sections[existing_index].line;
                diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        "DUPLICATE_SECTION",
                        source_name,
                        line_number,
                        format!("Duplicate section '{display_name}'."),
                        raw,
                    )
                    .with_related(source_name, first_line),
                );
                current_index = Some(existing_index);
            } else {
                sections.push(ScriptSection {
                    name: name.clone(),
                    display_name,
                    header: raw.trim().to_string(),
                    error_code: parts.error_code,
                    retry: parts.retry,
                    source: source_name.to_string(),
                    line: line_number,
                    data_entries: Vec::new(),
                    rows: Vec::new(),
                });
                let index = sections.len() - 1;
                section_index.insert(key, index);
                current_index = Some(index);
            }
            in_flow = false;
            continue;
        }

        let Some(section_index) = current_index else {
            if !in_flow && raw.contains('=') {
                diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    "KEY_OUTSIDE_SECTION",
                    source_name,
                    line_number,
                    "Assignment appears before any section header.",
                    raw,
                ));
            }
            continue;
        };

        if !raw.contains('=') {
            continue;
        }

        let Some((label_raw, raw_value, unterminated_quote)) = parse_script_row(raw) else {
            if raw.contains('|') {
                diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    "FUNCTION_ROW_INVALID",
                    source_name,
                    line_number,
                    "Function row must use label = \"...\" syntax.",
                    raw,
                ));
            } else if let Some((key, value)) = parse_data_assignment(raw) {
                sections[section_index].data_entries.push(DataEntry {
                    key,
                    value,
                    line: line_number,
                    raw: raw.to_string(),
                });
            }
            continue;
        };
        if unterminated_quote {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "UNTERMINATED_QUOTE",
                source_name,
                line_number,
                "Function row is missing its closing quote; the row was recovered for branch validation.",
                raw,
            ));
        }

        if !raw_value.contains('|') {
            sections[section_index].data_entries.push(DataEntry {
                key: label_raw,
                value: raw_value,
                line: line_number,
                raw: raw.to_string(),
            });
            continue;
        }
        let fields: Vec<String> = raw_value
            .split('|')
            .map(|field| field.trim().to_string())
            .collect();
        if fields.len() < CORE_FUNCTION_FIELD_COUNT {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "FUNCTION_FIELD_COUNT",
                source_name,
                line_number,
                format!("Function row has {} field(s); expected 7 core fields plus an optional ERRCODE field.", fields.len()),
                raw,
            ));
            continue;
        }
        if fields.len() > MAX_FUNCTION_FIELD_COUNT {
            diagnostics.push(Diagnostic::new(
                Severity::Warning,
                "FUNCTION_EXTRA_FIELDS",
                source_name,
                line_number,
                format!("Function row has {} fields; fields after the optional eighth ERRCODE field are not part of the standard template.", fields.len()),
                raw,
            ));
        }
        if !is_integer_wait_time(&fields[4]) {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "WAIT_TIME_NOT_INTEGER",
                source_name,
                line_number,
                format!("WAIT_TIME field must be an integer; found '{}'.", fields[4]),
                raw,
            ));
        }
        if fields.len() >= MAX_FUNCTION_FIELD_COUNT
            && !fields[7].is_empty()
            && !is_error_code_format(&fields[7])
        {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "ERROR_CODE_FORMAT",
                source_name,
                line_number,
                "The optional eighth field must use ERRCODE:<index> or ErrorCode:<index> format.",
                raw,
            ));
        }

        let (label, retry) = split_retry_label(&label_raw);
        let (dll_base_name, dll_suffixes, dll_invocation_mode) = parse_dll_invocation(&fields[0]);
        let row = ScriptRow {
            label,
            label_raw,
            retry,
            line: line_number,
            raw: raw.to_string(),
            raw_value,
            dll_name: fields.first().cloned().unwrap_or_default(),
            dll_base_name,
            dll_suffixes,
            dll_invocation_mode,
            dll_function: fields.get(1).cloned().unwrap_or_default(),
            criteria: fields.get(2).cloned().unwrap_or_default(),
            parameters: fields.get(3).cloned().unwrap_or_default(),
            timeout: fields.get(4).cloned().unwrap_or_default(),
            pass_path: fields.get(5).cloned().unwrap_or_default(),
            fail_path: fields.get(6).cloned().unwrap_or_default(),
            error_code: fields.get(7).cloned().filter(|value| !value.is_empty()),
            extra_fields: if fields.len() > MAX_FUNCTION_FIELD_COUNT {
                fields[MAX_FUNCTION_FIELD_COUNT..].to_vec()
            } else {
                Vec::new()
            },
            unterminated_quote,
        };
        sections[section_index].rows.push(row);
    }

    ParsedScriptSections {
        sections,
        diagnostics,
    }
}

pub fn parse_data_sections_text(text: &str, source_name: &str) -> Vec<DataSection> {
    let mut sections: Vec<DataSection> = Vec::new();
    let mut current_index: Option<usize> = None;

    for (line_index, raw) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if is_ignored_line(raw) {
            continue;
        }

        if let Some(display_name) = parse_any_section(raw) {
            let display_name = display_name.trim().to_string();
            let (name, _) = section_name(&display_name);
            sections.push(DataSection {
                source: source_name.to_string(),
                name,
                display_name,
                header: raw.trim().to_string(),
                line: line_number,
                entries: Vec::new(),
            });
            current_index = Some(sections.len() - 1);
            continue;
        }

        let Some(index) = current_index else {
            continue;
        };
        if let Some((key, value)) = parse_data_assignment(raw) {
            sections[index].entries.push(DataEntry {
                key,
                value,
                line: line_number,
                raw: raw.to_string(),
            });
        }
    }

    sections
        .into_iter()
        .filter(|section| !section.entries.is_empty())
        .collect()
}

fn is_integer_wait_time(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.eq_ignore_ascii_case("NULL")
        || (!trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_digit()))
}

fn parse_dll_invocation(value: &str) -> (String, Vec<String>, String) {
    let trimmed = value.trim();
    let mut parts = trimmed.split('#');
    let base_name = parts.next().unwrap_or_default().trim().to_string();
    let suffixes: Vec<String> = parts
        .filter_map(|part| {
            let suffix = part.trim();
            (!suffix.is_empty()).then(|| suffix.to_ascii_uppercase())
        })
        .collect();
    let mode = if suffixes.iter().any(|suffix| suffix == "PROXY") {
        "proxy"
    } else if suffixes.iter().any(|suffix| suffix == "QUICK") {
        "quick"
    } else {
        "normal"
    };
    (base_name, suffixes, mode.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rows_and_ignores_comments() {
        let parsed = parse_script_sections_text(
            "; A = \"DLL|NOPE|NULL|NULL|1|QUIT|FAIL\"\n[RUN#Retry:2]\nA#Retry:3 = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        assert_eq!(parsed.sections[0].retry, Some(2));
        assert_eq!(parsed.sections[0].rows[0].label, "A");
        assert_eq!(parsed.sections[0].rows[0].retry, Some(3));
    }

    #[test]
    fn parses_item_header_error_code_and_retry_in_any_order() {
        let parsed = parse_script_sections_text(
            "[GET_SERIAL_NUMBER#ErrCode:Get_SN_fail,Retry:2]\nA = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n[SECOND#Retry:3,ErrCode:Second_fail]\nA = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        assert_eq!(parsed.sections[0].name, "GET_SERIAL_NUMBER");
        assert_eq!(
            parsed.sections[0].error_code.as_deref(),
            Some("Get_SN_fail")
        );
        assert_eq!(parsed.sections[0].retry, Some(2));
        assert_eq!(parsed.sections[1].name, "SECOND");
        assert_eq!(
            parsed.sections[1].error_code.as_deref(),
            Some("Second_fail")
        );
        assert_eq!(parsed.sections[1].retry, Some(3));
    }

    #[test]
    fn keeps_unknown_hash_suffix_as_part_of_section_name() {
        let sections = parse_data_sections_text("[OSP#PROXY]\nDLL = TRUE\n", "RD_SETTING.ini");
        assert_eq!(sections[0].name, "OSP#PROXY");
    }

    #[test]
    fn parses_dll_suffixes_with_proxy_priority() {
        let parsed = parse_script_sections_text(
            "[RUN]\nA = \"DLLQSPR#QUICK|FUNC|NULL|NULL|1|QUIT|FAIL\"\nB = \"DLLOSP#PROXY|FUNC|NULL|NULL|1|QUIT|FAIL\"\nC = \"DLLSample#QUICK#PROXY|FUNC|NULL|NULL|1|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        let rows = &parsed.sections[0].rows;
        assert_eq!(rows[0].dll_base_name, "DLLQSPR");
        assert_eq!(rows[0].dll_suffixes, vec!["QUICK"]);
        assert_eq!(rows[0].dll_invocation_mode, "quick");
        assert_eq!(rows[1].dll_base_name, "DLLOSP");
        assert_eq!(rows[1].dll_suffixes, vec!["PROXY"]);
        assert_eq!(rows[1].dll_invocation_mode, "proxy");
        assert_eq!(rows[2].dll_base_name, "DLLSample");
        assert_eq!(rows[2].dll_suffixes, vec!["QUICK", "PROXY"]);
        assert_eq!(rows[2].dll_invocation_mode, "proxy");
    }

    #[test]
    fn parses_non_function_data_entries() {
        let parsed = parse_script_sections_text(
            "[TEST_PROGRAM_VER]\nSCRIPT_VERSION = \"HH5K_Wireless_2\"\n[INFORMATION]\nMODEL_NAME = HH5K\n",
            "MAIN_FLOW.ini",
        );
        assert_eq!(parsed.sections[0].data_entries[0].key, "SCRIPT_VERSION");
        assert_eq!(parsed.sections[1].data_entries[0].value, "HH5K");
        assert!(parsed.diagnostics.is_empty());
    }

    #[test]
    fn reports_non_integer_wait_time() {
        let parsed = parse_script_sections_text(
            "[RUN]\nA = \"DLL|FUNC|NULL|NULL|abc|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|item| item.code == "WAIT_TIME_NOT_INTEGER")
        );
    }

    #[test]
    fn accepts_null_wait_time() {
        let parsed = parse_script_sections_text(
            "[RUN]\nA = \"DLL|FUNC|NULL|NULL|NULL|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        assert!(
            !parsed
                .diagnostics
                .iter()
                .any(|item| item.code == "WAIT_TIME_NOT_INTEGER")
        );
    }

    #[test]
    fn parses_data_sections_without_function_diagnostics() {
        let sections = parse_data_sections_text(
            "[IQ_INFO]\nTESTER_TYPE = \"IQTYPE_XEL_M8X\"\nREQUEST_TIMEOUT = 60\n",
            "FACTORY_SETTING.ini",
        );
        assert_eq!(sections[0].name, "IQ_INFO");
        assert_eq!(sections[0].entries[0].value, "IQTYPE_XEL_M8X");
        assert_eq!(sections[0].entries[1].value, "60");
    }
}
