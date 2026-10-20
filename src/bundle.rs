use std::collections::HashSet;

use schemars::JsonSchema;
use script_checker::{
    analysis::{ContentAnalysisRequest, SourceFile, analyze_contents},
    models::{FlowKind, ScriptSection},
    parser::{
        common::{
            canonical_header, is_ignored_line, label_without_retry, parse_any_section,
            parse_flow_section, section_name,
        },
        main_flow::parse_main_flow_text,
        script_sections::parse_script_sections_text,
    },
};
use serde::{Deserialize, Serialize};

use crate::{Engine, Error, Result};

mod catalog;
pub mod compose;
pub mod plan;
mod semantics;
pub use semantics::{ExecutionEdge, ExecutionRow};

pub const MAX_TEXT_BYTES: usize = 1_048_576;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_EXPANDED_ROWS: usize = 16_384;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub name: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleDialect {
    Hh5k,
    CheckerLegacy,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub reference: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateBundleRequest {
    pub files: Vec<BundleFile>,
    pub selected_flow: String,
    pub dialect: BundleDialect,
    pub device_scope: Option<String>,
    #[serde(default)]
    pub runtime_bindings: Vec<RuntimeBinding>,
    #[serde(default)]
    pub sensitive_values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Valid,
    Invalid,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct BundleDiagnostic {
    pub severity: &'static str,
    pub layer: &'static str,
    pub code: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub section: Option<String>,
    pub row: Option<String>,
    pub field: Option<String>,
    pub evidence: Option<String>,
}

impl BundleDiagnostic {
    fn new(layer: &'static str, code: &str, message: &str) -> Self {
        Self {
            severity: "error",
            layer,
            code: code.into(),
            message: message.into(),
            file: None,
            line: None,
            section: None,
            row: None,
            field: None,
            evidence: None,
        }
    }

    fn at(mut self, file: &str, line: usize, section: Option<&str>, row: Option<&str>) -> Self {
        self.file = Some(file.into());
        self.line = (line > 0).then_some(line);
        self.section = section.map(str::to_string);
        self.row = row.map(str::to_string);
        self
    }

    fn field(mut self, field: &str, evidence: Option<&str>) -> Self {
        self.field = Some(field.into());
        self.evidence = evidence.map(str::to_string);
        self
    }

    fn unchecked(mut self) -> Self {
        self.severity = "unsupported";
        self
    }
}

#[derive(Debug, Serialize)]
pub struct BundleLayers {
    pub structure: CheckStatus,
    pub control_flow: CheckStatus,
    pub references: CheckStatus,
    pub catalog: CheckStatus,
}

#[derive(Debug, Serialize)]
pub struct BundleRow {
    pub label: String,
    pub line: usize,
    pub raw: String,
    pub segments: Vec<String>,
    pub device: String,
    pub function: String,
    pub parameters: String,
    pub criteria: String,
    pub timeout: String,
    pub pass_path: String,
    pub fail_path: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BundleSection {
    pub file: String,
    pub name: String,
    pub line: usize,
    pub rows: Vec<BundleRow>,
}

#[derive(Debug, Serialize)]
pub struct BundleReport {
    pub status: CheckStatus,
    pub selected_flow: String,
    pub dialect: BundleDialect,
    pub layers: BundleLayers,
    pub diagnostics: Vec<BundleDiagnostic>,
    pub source_files: Vec<BundleFile>,
    pub script_sections: Vec<BundleSection>,
    pub execution: Vec<ExecutionRow>,
    pub execution_edges: Vec<ExecutionEdge>,
    pub runtime_verification: &'static str,
    pub hardware_verification: &'static str,
    pub packaging: &'static str,
}

fn invalid_request(message: &str) -> Error {
    Error::InvalidInput {
        field: "bundle".into(),
        message: message.into(),
    }
}

impl ValidateBundleRequest {
    pub fn check_bounds(&self) -> Result<()> {
        if self.files.is_empty() || self.files.len() > 16 {
            return Err(invalid_request("supply between 1 and 16 logical files"));
        }
        if self.selected_flow.trim().is_empty() || self.selected_flow.len() > 256 {
            return Err(invalid_request(
                "supply an explicit TEST FLOW header of at most 256 bytes",
            ));
        }
        if !parse_flow_section(&self.selected_flow)
            .is_some_and(|flow| flow.kind == FlowKind::Test && !flow.station.is_empty())
        {
            return Err(invalid_request(
                "selected_flow must be a complete TEST FLOW header",
            ));
        }
        if self.runtime_bindings.len() > 128 || self.sensitive_values.len() > 128 {
            return Err(invalid_request(
                "at most 128 runtime bindings and sensitive values are supported",
            ));
        }
        let mut bytes =
            self.selected_flow.len() + self.device_scope.as_ref().map_or(0, String::len);
        let mut records = 0;
        let mut names = HashSet::new();
        for file in &self.files {
            if file.name.is_empty()
                || file.name.len() > 128
                || !file
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                || matches!(file.name.as_str(), "." | "..")
                || !names.insert(file.name.to_ascii_lowercase())
            {
                return Err(invalid_request(
                    "logical file names must be unique bare ASCII names, not paths or URLs",
                ));
            }
            bytes += file.name.len() + file.text.len();
            for line in file.text.lines() {
                if line.len() > 8192 {
                    return Err(invalid_request("a source line exceeds 8192 bytes"));
                }
                records += 1;
            }
        }
        for binding in &self.runtime_bindings {
            if !["*E:", "*I:", "*T:"]
                .iter()
                .any(|prefix| binding.reference.starts_with(prefix))
                || !binding.reference.ends_with('#')
                || binding.reference.len() < 5
                || binding.reference[3..binding.reference.len() - 1].contains(['#', '\r', '\n'])
            {
                return Err(invalid_request(
                    "runtime bindings require complete *E:, *I: or *T: reference tokens ending with #",
                ));
            }
            bytes += binding.reference.len() + binding.value.as_ref().map_or(0, String::len);
        }
        bytes += self.sensitive_values.iter().map(String::len).sum::<usize>();
        if bytes > MAX_TEXT_BYTES || records > MAX_RECORDS {
            return Err(invalid_request(
                "bundle exceeds 1048576 text bytes or 4096 source records",
            ));
        }
        if let Some(main) = self
            .files
            .iter()
            .find(|file| file.name.eq_ignore_ascii_case("MAIN_FLOW.ini"))
        {
            let parsed = parse_script_sections_text(&main.text, &main.name);
            let parsed_macros = self
                .files
                .iter()
                .find(|file| file.name.eq_ignore_ascii_case("MACRO_LIST.ini"))
                .map(|file| parse_script_sections_text(&file.text, &file.name));
            let flows = parse_main_flow_text(&main.text, &main.name);
            let expanded_rows = flows
                .flows
                .iter()
                .filter(|flow| {
                    flow.kind == FlowKind::Test
                        && canonical_header(&flow.header) == canonical_header(&self.selected_flow)
                })
                .flat_map(|flow| &flow.items)
                .filter_map(|item| parsed.section_by_name(item))
                .flat_map(|section| &section.rows)
                .map(|row| {
                    let macro_rows = if row.dll_name.eq_ignore_ascii_case("MACRO") {
                        parsed_macros
                            .as_ref()
                            .and_then(|macros| macros.section_by_name(&row.dll_function))
                            .map_or(0, |section| section.rows.len())
                    } else {
                        0
                    };
                    macro_rows + 1
                })
                .sum::<usize>();
            if expanded_rows > MAX_EXPANDED_ROWS {
                return Err(invalid_request(
                    "checker expansion estimate exceeds 16384 rows",
                ));
            }
        }
        Ok(())
    }
}

pub fn validate(request: ValidateBundleRequest, engine: &Engine) -> Result<BundleReport> {
    validate_with_secrets(request, engine, &[]).map(|(report, _)| report)
}

fn validate_with_secrets(
    request: ValidateBundleRequest,
    engine: &Engine,
    declared_secrets: &[String],
) -> Result<(BundleReport, Vec<String>)> {
    request.check_bounds()?;
    let main = request
        .files
        .iter()
        .find(|file| file.name.eq_ignore_ascii_case("MAIN_FLOW.ini"))
        .ok_or_else(|| invalid_request("MAIN_FLOW.ini is required to select a flow"))?;
    let macros = request
        .files
        .iter()
        .find(|file| file.name.eq_ignore_ascii_case("MACRO_LIST.ini"));
    let parsed = parse_script_sections_text(&main.text, &main.name);
    let parsed_macros = macros.map(|file| parse_script_sections_text(&file.text, &file.name));
    let flows = parse_main_flow_text(&main.text, &main.name);
    let source = |file: &BundleFile| SourceFile {
        name: file.name.clone(),
        text: file.text.clone(),
    };
    let analysis = analyze_contents(ContentAnalysisRequest {
        main_flow: source(main),
        macro_list: macros.map(source),
        auxiliary_files: request
            .files
            .iter()
            .filter(|file| {
                !file.name.eq_ignore_ascii_case("MAIN_FLOW.ini")
                    && !file.name.eq_ignore_ascii_case("MACRO_LIST.ini")
            })
            .map(source)
            .collect(),
        required_files: Vec::new(),
        flow_header: request.selected_flow.clone(),
    })
    .map_err(|_| invalid_request("checker could not analyze supplied contents"))?;
    let mut diagnostics = Vec::new();
    for issue in &analysis.diagnostics {
        if !matches!(
            issue.code.as_str(),
            "UNTERMINATED_QUOTE"
                | "FUNCTION_ROW_INVALID"
                | "FUNCTION_FIELD_COUNT"
                | "DUPLICATE_SECTION"
                | "KEY_OUTSIDE_SECTION"
                | "FLOW_HEADER_NOT_FOUND"
                | "DUPLICATE_FLOW_HEADER"
                | "DUPLICATE_INIT_FLOW_NAME"
                | "DUPLICATE_FINAL_FLOW_NAME"
                | "FLOW_HEADER_KIND_INVALID"
                | "FLOW_ITEM_WHITESPACE"
                | "FLOW_ROW_INVALID"
        ) {
            continue;
        }
        let section = analysis.script_sections.iter().find(|section| {
            section.source == issue.file && section.rows.iter().any(|row| row.line == issue.line)
        });
        let row =
            section.and_then(|section| section.rows.iter().find(|row| row.line == issue.line));
        let (source_section, source_row, evidence) =
            source_context(&request.files, &issue.file, issue.line);
        diagnostics.push(BundleDiagnostic {
            severity: "error",
            layer: if issue.code == "FLOW_HEADER_NOT_FOUND" {
                "control_flow"
            } else {
                "structure"
            },
            code: issue.code.clone(),
            message: match issue.code.as_str() {
                "UNTERMINATED_QUOTE" => "Missing closing quote; recovered row remains invalid.",
                "FLOW_HEADER_NOT_FOUND" => "Selected TEST FLOW was not found.",
                _ => "Invalid bundle structure; inspect the located source.",
            }
            .into(),
            file: Some(issue.file.clone()),
            line: (issue.line > 0).then_some(issue.line),
            section: section
                .map(|section| section.name.clone())
                .or(source_section),
            row: row.map(|row| row.label_raw.clone()).or(source_row),
            field: Some("row".into()),
            evidence,
        });
    }
    validate_source_structure(&request.files, &mut diagnostics);
    if let Some(selected) = flows.flows.iter().find(|flow| {
        flow.kind == FlowKind::Test
            && canonical_header(&flow.header) == canonical_header(&request.selected_flow)
    }) {
        if selected.rows.is_empty() {
            diagnostics.push(
                BundleDiagnostic::new(
                    "control_flow",
                    "FLOW_EMPTY",
                    "Selected flow has no active items.",
                )
                .at(&main.name, selected.line, Some(&selected.header), None),
            );
        }
        for item in &selected.rows {
            if !parsed.sections.iter().any(|section| {
                section.name.eq_ignore_ascii_case(&item.item) && !section.rows.is_empty()
            }) {
                diagnostics.push(
                    BundleDiagnostic::new(
                        "control_flow",
                        "FLOW_ITEM_SECTION_MISSING",
                        "Selected flow item has no executable implementation.",
                    )
                    .at(
                        &main.name,
                        item.line,
                        Some(&selected.header),
                        Some(&item.key),
                    )
                    .field("item", Some(&item.item)),
                );
            }
        }
    }
    validate_rows(
        &analysis.script_sections,
        parsed_macros
            .as_ref()
            .map(|parsed| parsed.sections.as_slice()),
        request.dialect,
        &mut diagnostics,
    );
    let mut secrets = diagnostic_secrets(&request)?;
    secrets.extend(
        declared_secrets
            .iter()
            .filter(|secret| !secret.is_empty())
            .cloned(),
    );
    let (mut execution, execution_edges) =
        semantics::analyze(&analysis, &request, &mut diagnostics, &mut secrets);
    catalog::validate(
        engine,
        &execution,
        request.device_scope.as_deref(),
        &mut diagnostics,
    );
    if !request.runtime_bindings.is_empty() {
        diagnostics.push(
            BundleDiagnostic::new(
                "references",
                "RUNTIME_BINDINGS_UNCHECKED",
                "Declared runtime bindings do not prove runtime values or availability.",
            )
            .unchecked(),
        );
    }
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets.dedup();
    for row in &mut execution {
        for field in [
            &mut row.file,
            &mut row.section,
            &mut row.row,
            &mut row.device,
            &mut row.function,
            &mut row.parameters,
            &mut row.criteria,
            &mut row.timeout,
            &mut row.pass_path,
            &mut row.fail_path,
        ] {
            let redacted = redact(field, &secrets);
            row.redacted |= redacted != *field;
            *field = redacted;
        }
    }
    for issue in &mut diagnostics {
        issue.message = redact(&issue.message, &secrets);
        for field in [
            &mut issue.file,
            &mut issue.section,
            &mut issue.row,
            &mut issue.field,
            &mut issue.evidence,
        ]
        .into_iter()
        .flatten()
        {
            *field = redact(field, &secrets);
        }
    }
    let layer_status = |layer| {
        if diagnostics
            .iter()
            .any(|issue| issue.layer == layer && issue.severity == "error")
        {
            CheckStatus::Invalid
        } else if diagnostics
            .iter()
            .any(|issue| issue.layer == layer && issue.severity == "unsupported")
        {
            CheckStatus::Incomplete
        } else {
            CheckStatus::Valid
        }
    };
    let layers = BundleLayers {
        structure: layer_status("structure"),
        control_flow: layer_status("control_flow"),
        references: layer_status("references"),
        catalog: layer_status("catalog"),
    };
    let status = if diagnostics.iter().any(|issue| issue.severity == "error") {
        CheckStatus::Invalid
    } else if diagnostics
        .iter()
        .any(|issue| issue.severity == "unsupported")
    {
        CheckStatus::Incomplete
    } else {
        CheckStatus::Valid
    };
    let report = BundleReport {
        status,
        selected_flow: redact(&request.selected_flow, &secrets),
        dialect: request.dialect,
        layers,
        diagnostics,
        execution,
        execution_edges,
        source_files: request.files,
        script_sections: analysis
            .script_sections
            .into_iter()
            .map(|section| BundleSection {
                file: section.source,
                name: section.name,
                line: section.line,
                rows: section
                    .rows
                    .into_iter()
                    .map(|row| BundleRow {
                        label: row.label_raw,
                        line: row.line,
                        raw: row.raw,
                        segments: row.raw_value.split('|').map(str::to_string).collect(),
                        device: row.dll_name,
                        function: row.dll_function,
                        parameters: row.criteria,
                        criteria: row.parameters,
                        timeout: row.timeout,
                        pass_path: row.pass_path,
                        fail_path: row.fail_path,
                        error_code: row.error_code,
                    })
                    .collect(),
            })
            .collect(),
        runtime_verification: "unchecked",
        hardware_verification: "unchecked",
        packaging: "unchecked",
    };
    Ok((report, secrets))
}

fn source_context(
    files: &[BundleFile],
    name: &str,
    line: usize,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(file) = files.iter().find(|file| file.name == name) else {
        return (None, None, None);
    };
    let mut section = None;
    let mut source_line = None;
    for raw in file.text.lines().take(line) {
        if let Some(header) = parse_any_section(raw) {
            section = Some(section_name(&header).0);
        }
        source_line = Some(raw);
    }
    let row = source_line
        .and_then(|raw| raw.split_once('='))
        .map(|(label, _)| label.trim().to_string());
    let evidence = source_line.map(|raw| {
        let payload = raw.split_once('=').map_or(raw, |(_, value)| value);
        format!(
            "quotes={}; fields={}",
            payload.matches('"').count(),
            payload.split('|').count()
        )
    });
    (section, row, evidence)
}

fn validate_source_structure(files: &[BundleFile], diagnostics: &mut Vec<BundleDiagnostic>) {
    for file in files {
        let mut headers = HashSet::new();
        let mut section = None;
        for (index, raw) in file.text.lines().enumerate() {
            if is_ignored_line(raw) {
                continue;
            }
            if let Some(header) = parse_any_section(raw) {
                let identity = section_name(&header).0.to_ascii_lowercase();
                if !headers.insert(identity)
                    && !diagnostics.iter().any(|issue| {
                        issue.file.as_deref() == Some(&file.name)
                            && issue.line == Some(index + 1)
                            && issue.code.starts_with("DUPLICATE_")
                    })
                {
                    diagnostics.push(BundleDiagnostic::new("structure", "DUPLICATE_SECTION", "Section identity is ambiguous; no definition is selected as authoritative.").at(&file.name, index + 1, Some(&header), None));
                }
                section = Some(header);
                continue;
            }
            if raw.trim_start().starts_with('[') {
                diagnostics.push(
                    BundleDiagnostic::new(
                        "structure",
                        "MALFORMED_SECTION",
                        "Section header is missing its closing bracket.",
                    )
                    .at(&file.name, index + 1, section.as_deref(), None),
                );
            }
            if let Some((label, value)) = raw.split_once('=') {
                let value = value.trim();
                if value.starts_with('"')
                    && (value.len() == 1 || !value.ends_with('"'))
                    && !diagnostics.iter().any(|issue| {
                        issue.code == "UNTERMINATED_QUOTE"
                            && issue.file.as_deref() == Some(&file.name)
                            && issue.line == Some(index + 1)
                    })
                {
                    diagnostics.push(
                        BundleDiagnostic::new(
                            "structure",
                            "UNTERMINATED_QUOTE",
                            "Missing closing quote; source remains invalid.",
                        )
                        .at(
                            &file.name,
                            index + 1,
                            section.as_deref(),
                            Some(label.trim()),
                        )
                        .field("row", None),
                    );
                }
                if value.starts_with('"')
                    && value.ends_with('"')
                    && value.len() > 1
                    && value[1..value.len() - 1].contains('"')
                {
                    diagnostics.push(
                        BundleDiagnostic::new(
                            "structure",
                            "MALFORMED_QUOTE",
                            "Embedded quotes have no audited escaping scheme.",
                        )
                        .at(
                            &file.name,
                            index + 1,
                            section.as_deref(),
                            Some(label.trim()),
                        )
                        .field("row", None),
                    );
                }
            }
        }
    }
}

fn validate_rows(
    sections: &[ScriptSection],
    macros: Option<&[ScriptSection]>,
    dialect: BundleDialect,
    diagnostics: &mut Vec<BundleDiagnostic>,
) {
    for section in sections {
        let labels: HashSet<_> = section
            .rows
            .iter()
            .map(|row| row.label.to_ascii_lowercase())
            .collect();
        for row in &section.rows {
            let located = |layer, code, message| {
                BundleDiagnostic::new(layer, code, message).at(
                    &section.source,
                    row.line,
                    Some(&section.name),
                    Some(&row.label_raw),
                )
            };
            if row.raw_value.split('|').count() > 8 {
                let mut issue = located(
                    "structure",
                    "FUNCTION_EXTRA_FIELDS",
                    "Fields beyond the optional eighth error code are not supported.",
                )
                .field("row", None);
                if dialect == BundleDialect::CheckerLegacy {
                    issue = issue.unchecked();
                }
                diagnostics.push(issue);
            }
            if !row.timeout.eq_ignore_ascii_case("NULL")
                && !semantics::has_reference(&row.timeout)
                && (row.timeout.is_empty()
                    || !row.timeout.bytes().all(|byte| byte.is_ascii_digit()))
            {
                diagnostics.push(
                    located(
                        "structure",
                        "WAIT_TIME_NOT_INTEGER",
                        "Timeout must contain decimal digits or NULL.",
                    )
                    .field("timeout", None),
                );
            }
            if let Some(code) = &row.error_code {
                let valid = code.split_once(':').is_some_and(|(prefix, value)| {
                    (prefix.eq_ignore_ascii_case("ERRCODE")
                        || prefix.eq_ignore_ascii_case("ErrorCode"))
                        && !value.trim().is_empty()
                });
                if !valid {
                    diagnostics.push(located("structure", "ERROR_CODE_FORMAT", "Optional error code must use ERRCODE:<opaque token> or ErrorCode:<opaque token>.").field("error_code", None));
                } else {
                    let mut warning = located("structure", "ERROR_CODE_OPAQUE", "Error code is preserved; its runtime meaning is not defined by the catalog.").field("error_code", None);
                    warning.severity = "warning";
                    diagnostics.push(warning);
                }
            }
            if row.dll_name.is_empty() || row.dll_function.is_empty() {
                diagnostics.push(located(
                    "structure",
                    "FUNCTION_IDENTITY_EMPTY",
                    "Script device and Function must be nonempty.",
                ));
            }
            for suffix in row.dll_name.split('#').skip(1) {
                if !["QUICK", "PROXY"].contains(&suffix) {
                    diagnostics.push(
                        located(
                            "structure",
                            "DISPATCH_SUFFIX_UNCHECKED",
                            "Dispatch suffix is preserved but is not an audited execution mode.",
                        )
                        .field("device", None)
                        .unchecked(),
                    );
                }
            }
            for (field, target) in [("pass_path", &row.pass_path), ("fail_path", &row.fail_path)] {
                if semantics::has_reference(target) {
                    continue;
                }
                if ["NEXT", "QUIT", "FAIL", "PASS", "END"].contains(&target.as_str()) {
                    continue;
                }
                if ["NEXT", "QUIT", "FAIL", "PASS", "END"]
                    .iter()
                    .any(|token| target.eq_ignore_ascii_case(token))
                {
                    let mut issue = located("control_flow", "DIALECT_TOKEN_CASE", "HH5K control tokens require uppercase; legacy interpretation is not runtime proof.").field(field, Some(target));
                    if dialect == BundleDialect::CheckerLegacy {
                        issue = issue.unchecked();
                    }
                    diagnostics.push(issue);
                } else if !labels.contains(&label_without_retry(target).to_ascii_lowercase()) {
                    diagnostics.push(
                        located(
                            "control_flow",
                            "BRANCH_TARGET_MISSING",
                            "Branch target is not defined in this section.",
                        )
                        .field(field, Some(target)),
                    );
                }
            }
            if row.dll_name.eq_ignore_ascii_case("MACRO")
                && !semantics::has_reference(&row.dll_function)
            {
                match macros {
                    None => diagnostics.push(located("control_flow", "MACRO_FILE_MISSING", "Supply MACRO_LIST.ini to inspect this macro dependency.").field("function", Some(&row.dll_function)).unchecked()),
                    Some(macros) if !macros.iter().any(|target| target.name.eq_ignore_ascii_case(&row.dll_function) && !target.rows.is_empty()) => diagnostics.push(located("control_flow", "MACRO_TARGET_MISSING", "Macro has no executable implementation in supplied MACRO_LIST.ini.").field("function", Some(&row.dll_function))),
                    Some(_) => {},
                }
            }
        }
    }
}

fn diagnostic_secrets(request: &ValidateBundleRequest) -> Result<Vec<String>> {
    let mut secrets = request.sensitive_values.clone();
    secrets.extend(
        request
            .runtime_bindings
            .iter()
            .filter_map(|binding| binding.value.clone()),
    );
    for pattern in [
        r#"(?i)(?:password|passwd|pwd|secret|token|credential|api[_-]?key)\s*[:=]\s*["']?([^"'&;|\r\n]+)"#,
        r#"(?i)[a-z][a-z0-9+.-]*://[^:/\s"']+:([^@/\s"']+)@"#,
    ] {
        let matcher = regex::Regex::new(pattern)
            .map_err(|_| invalid_request("diagnostic redaction is unavailable"))?;
        for file in &request.files {
            secrets.extend(matcher.captures_iter(&file.text).filter_map(|capture| {
                capture
                    .get(1)
                    .map(|value| value.as_str().trim().to_string())
            }));
        }
    }
    secrets.retain(|secret| !secret.is_empty());
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets.dedup();
    Ok(secrets)
}

fn redact(value: &str, secrets: &[String]) -> String {
    let mut redacted = String::with_capacity(value.len());
    let mut offset = 0;
    while let Some(tail) = value.get(offset..).filter(|tail| !tail.is_empty()) {
        if let Some(secret) = secrets
            .iter()
            .filter(|secret| {
                !secret.is_empty()
                    && tail.starts_with(secret.as_str())
                    && (!tail.starts_with("[REDACTED]") || secret.starts_with("[REDACTED]"))
            })
            .max_by_key(|secret| secret.len())
        {
            redacted.push_str("[REDACTED]");
            offset += secret.len();
        } else if tail.starts_with("[REDACTED]") {
            redacted.push_str("[REDACTED]");
            offset += "[REDACTED]".len();
        } else if let Some(character) = tail.chars().next() {
            redacted.push(character);
            offset += character.len_utf8();
        }
    }
    redacted
}
