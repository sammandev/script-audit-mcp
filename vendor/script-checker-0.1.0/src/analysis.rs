use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostics::{Diagnostic, Severity, file_name};
use crate::graph::{ScriptFlowGraph, build_script_flow_graph};
use crate::io::read_text_lossy;
use crate::local_time::local_iso8601;
use crate::models::{
    DataEntry, DataSection, DllInvocationContext, Flow, FlowKind, ItemHeaderContext, ScriptInfo,
    ScriptRow, ScriptSection, VariableReference,
};
use crate::parser::common::{canonical_header, case_key, is_terminal_token, label_without_retry};
use crate::parser::main_flow::parse_main_flow_text;
use crate::parser::script_sections::{
    ParsedScriptSections, parse_data_sections_text, parse_script_sections_text,
};

#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    pub scripts_root: Option<PathBuf>,
    pub main_flow: Option<PathBuf>,
    pub macro_list: Option<PathBuf>,
    pub flow_header: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub name: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ContentAnalysisRequest {
    pub main_flow: SourceFile,
    pub macro_list: Option<SourceFile>,
    pub auxiliary_files: Vec<SourceFile>,
    pub required_files: Vec<String>,
    pub flow_header: String,
}

#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisInputs {
    pub script_root: Option<String>,
    pub main_flow: Option<String>,
    pub macro_list: Option<String>,
    pub flow_header: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnalysisCounts {
    pub errors: usize,
    pub warnings: usize,
    pub flows: usize,
    pub items: usize,
    pub sections: usize,
    pub nodes: usize,
    pub edges: usize,
    pub issues: usize,
    pub data_sections: usize,
    pub data_entries: usize,
    pub variable_references: usize,
    pub variables_resolved: usize,
    pub variables_unresolved: usize,
    pub variables_dynamic: usize,
}

#[derive(Debug, Clone)]
pub struct AnalysisOutput {
    pub schema_version: String,
    pub created_at: String,
    pub tool: ToolInfo,
    pub status: String,
    pub inputs: AnalysisInputs,
    pub script_info: ScriptInfo,
    pub counts: AnalysisCounts,
    pub flows: Vec<Flow>,
    pub item_headers: Vec<ItemHeaderContext>,
    pub dll_invocations: Vec<DllInvocationContext>,
    pub data_sections: Vec<DataSection>,
    pub variable_references: Vec<VariableReference>,
    pub diagnostics: Vec<Diagnostic>,
    pub graph: Option<ScriptFlowGraph>,
    pub source_files: Vec<SourceFile>,
    pub script_sections: Vec<ScriptSection>,
}

#[derive(Debug, Clone)]
struct RuntimeVariableOrigin {
    source: String,
    line: usize,
}

#[derive(Debug, Default)]
struct RuntimeVariableSources {
    sections: HashMap<String, RuntimeVariableOrigin>,
    keys: HashMap<String, RuntimeVariableOrigin>,
}

impl RuntimeVariableSources {
    fn insert_section(&mut self, name: &str, source: &str, line: usize) {
        self.sections
            .entry(case_key(name))
            .or_insert_with(|| RuntimeVariableOrigin {
                source: source.to_string(),
                line,
            });
    }

    fn insert_key(&mut self, header: &str, key: &str, source: &str, line: usize) {
        self.keys
            .entry(variable_key(header, key))
            .or_insert_with(|| RuntimeVariableOrigin {
                source: source.to_string(),
                line,
            });
    }

    fn section_origin(&self, name: &str) -> Option<&RuntimeVariableOrigin> {
        self.sections.get(&case_key(name))
    }

    fn key_origin(&self, header: &str, key: &str) -> Option<&RuntimeVariableOrigin> {
        self.keys.get(&variable_key(header, key))
    }
}

pub fn list_flows(main_flow: &Path) -> Result<Vec<String>, String> {
    let text = read_text_lossy(main_flow)?;
    let parsed = parse_main_flow_text(&text, &file_name(main_flow));
    Ok(parsed
        .flows
        .into_iter()
        .filter(|flow| flow.kind == FlowKind::Test)
        .map(|flow| flow.header)
        .collect())
}

pub fn analyze(request: AnalysisRequest) -> Result<AnalysisOutput, String> {
    let main_flow_path = resolve_main_flow(&request)?;
    let macro_list_path = resolve_macro_list(&request);
    let main_flow = SourceFile {
        name: file_name(&main_flow_path),
        text: read_text_lossy(&main_flow_path)?,
    };
    let mut diagnostics = Vec::new();
    let macro_list = match macro_list_path.as_ref() {
        Some(path) if path.is_file() => Some(SourceFile {
            name: file_name(path),
            text: read_text_lossy(path)?,
        }),
        Some(path) => {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "SCRIPT_FILE_MISSING",
                file_name(path),
                0,
                format!("Required script file '{}' is missing.", file_name(path)),
                "",
            ));
            None
        }
        None => None,
    };
    let auxiliary_files =
        collect_ini_sources(&request, &main_flow_path, macro_list_path.as_deref())?;
    Ok(analyze_loaded(
        main_flow,
        macro_list,
        auxiliary_files,
        AnalysisInputs {
            script_root: request.scripts_root.as_ref().map(|path| path_string(path)),
            main_flow: Some(path_string(&main_flow_path)),
            macro_list: macro_list_path.as_ref().map(|path| path_string(path)),
            flow_header: request.flow_header,
        },
        diagnostics,
    ))
}

pub fn analyze_contents(request: ContentAnalysisRequest) -> Result<AnalysisOutput, String> {
    if request.flow_header.trim().is_empty() {
        return Err("provide an explicit TEST FLOW header".to_string());
    }
    let mut names = HashSet::new();
    for source in std::iter::once(&request.main_flow)
        .chain(request.macro_list.iter())
        .chain(&request.auxiliary_files)
    {
        if source.name.trim().is_empty() || !names.insert(case_key(&source.name)) {
            return Err("supplied logical file names must be nonempty and unique".to_string());
        }
    }
    let diagnostics = request
        .required_files
        .iter()
        .filter(|name| !names.contains(&case_key(name)))
        .map(|name| {
            Diagnostic::new(
                Severity::Error,
                "SCRIPT_FILE_MISSING",
                name,
                0,
                format!("Required script file '{name}' is missing."),
                "",
            )
        })
        .collect();
    let inputs = AnalysisInputs {
        script_root: None,
        main_flow: Some(request.main_flow.name.clone()),
        macro_list: request
            .macro_list
            .as_ref()
            .map(|source| source.name.clone()),
        flow_header: Some(request.flow_header),
    };
    Ok(analyze_loaded(
        request.main_flow,
        request.macro_list,
        request.auxiliary_files,
        inputs,
        diagnostics,
    ))
}

fn analyze_loaded(
    main_flow: SourceFile,
    macro_list: Option<SourceFile>,
    auxiliary_files: Vec<SourceFile>,
    mut inputs: AnalysisInputs,
    loading_diagnostics: Vec<Diagnostic>,
) -> AnalysisOutput {
    let main_source_name = &main_flow.name;
    let parsed_main = parse_main_flow_text(&main_flow.text, main_source_name);
    let main_sections = parse_script_sections_text(&main_flow.text, main_source_name);
    let mut diagnostics = parsed_main.diagnostics;
    diagnostics.extend(main_sections.diagnostics.clone());
    let macro_sections = macro_list.as_ref().map(|source| {
        let parsed = parse_script_sections_text(&source.text, &source.name);
        diagnostics.extend(parsed.diagnostics.clone());
        parsed
    });
    diagnostics.extend(loading_diagnostics);

    validate_flows(
        &parsed_main.flows,
        &main_sections,
        main_source_name,
        &mut diagnostics,
    );
    validate_branch_targets(&main_sections, &mut diagnostics);
    if let Some(macros) = macro_sections.as_ref() {
        validate_branch_targets(macros, &mut diagnostics);
        validate_macro_calls(&main_sections, macros, main_source_name, &mut diagnostics);
    }
    let mut data_sections = collect_data_sections(&main_sections);
    if let Some(macros) = macro_sections.as_ref() {
        data_sections.extend(collect_data_sections(macros));
    }
    for source in &auxiliary_files {
        data_sections.extend(parse_data_sections_text(&source.text, &source.name));
    }
    let script_info = collect_script_info(&data_sections);
    let item_headers = collect_item_header_contexts(&main_sections, macro_sections.as_ref());
    let dll_invocations = collect_dll_invocation_contexts(&main_sections, macro_sections.as_ref());
    let runtime_variables =
        collect_runtime_variable_sources(&main_sections, macro_sections.as_ref());
    let variable_references = collect_variable_references(
        &main_sections,
        macro_sections.as_ref(),
        &data_sections,
        &runtime_variables,
    );

    let selected_flow = select_flow(
        &parsed_main.flows,
        inputs.flow_header.as_deref(),
        main_source_name,
        &mut diagnostics,
    );
    let graph = selected_flow
        .map(|flow| build_script_flow_graph(flow, &main_sections, macro_sections.as_ref()));

    let error_count = diagnostics
        .iter()
        .filter(|item| item.severity == Severity::Error)
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|item| item.severity == Severity::Warning)
        .count();
    let graph_issue_count = graph.as_ref().map(|item| item.issues.len()).unwrap_or(0);
    let status = if error_count > 0 {
        "error"
    } else if graph_issue_count > 0 {
        "issues"
    } else if warning_count > 0 {
        "warning"
    } else {
        "ok"
    };

    inputs.flow_header = selected_flow
        .map(|flow| flow.header.clone())
        .or(inputs.flow_header);
    let mut script_sections = main_sections.sections.clone();
    if let Some(macros) = &macro_sections {
        script_sections.extend(macros.sections.clone());
    }
    let source_files = std::iter::once(main_flow)
        .chain(macro_list)
        .chain(auxiliary_files)
        .collect();

    AnalysisOutput {
        schema_version: "1.0".to_string(),
        created_at: local_iso8601(),
        tool: ToolInfo {
            name: "script-checker".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        status: status.to_string(),
        inputs,
        script_info,
        counts: AnalysisCounts {
            errors: error_count,
            warnings: warning_count,
            flows: parsed_main
                .flows
                .iter()
                .filter(|flow| flow.kind == FlowKind::Test)
                .count(),
            items: parsed_main
                .flows
                .iter()
                .filter(|flow| flow.kind == FlowKind::Test)
                .map(|flow| flow.items.len())
                .sum(),
            sections: main_sections.sections.len()
                + macro_sections
                    .as_ref()
                    .map(|parsed| parsed.sections.len())
                    .unwrap_or(0),
            nodes: graph.as_ref().map(|item| item.node_count).unwrap_or(0),
            edges: graph.as_ref().map(|item| item.edge_count).unwrap_or(0),
            issues: graph_issue_count,
            data_sections: data_sections.len(),
            data_entries: data_sections
                .iter()
                .map(|section| section.entries.len())
                .sum(),
            variable_references: variable_references.len(),
            variables_resolved: variable_references
                .iter()
                .filter(|item| item.status == "resolved")
                .count(),
            variables_unresolved: variable_references
                .iter()
                .filter(|item| item.status.starts_with("unresolved"))
                .count(),
            variables_dynamic: variable_references
                .iter()
                .filter(|item| item.status == "dynamic")
                .count(),
        },
        flows: parsed_main.flows,
        item_headers,
        dll_invocations,
        data_sections,
        variable_references,
        diagnostics,
        graph,
        source_files,
        script_sections,
    }
}

fn collect_script_info(data_sections: &[DataSection]) -> ScriptInfo {
    ScriptInfo {
        script_version: data_entry_value(data_sections, "TEST_PROGRAM_VER", "SCRIPT_VERSION"),
        program_version: data_entry_value(data_sections, "TEST_PROGRAM_VER", "PROGRAM_VERSION"),
        ver: data_entry_value(data_sections, "Script_Info", "Ver"),
        model_name: data_entry_value(data_sections, "INFORMATION", "MODEL_NAME"),
    }
}

fn collect_item_header_contexts(
    main_sections: &ParsedScriptSections,
    macro_sections: Option<&ParsedScriptSections>,
) -> Vec<ItemHeaderContext> {
    let mut contexts = Vec::new();
    append_item_header_contexts(main_sections, &mut contexts);
    if let Some(sections) = macro_sections {
        append_item_header_contexts(sections, &mut contexts);
    }
    contexts
}

fn append_item_header_contexts(
    sections: &ParsedScriptSections,
    contexts: &mut Vec<ItemHeaderContext>,
) {
    contexts.extend(
        sections
            .sections
            .iter()
            .filter(|section| section.error_code.is_some() || section.retry.is_some())
            .map(|section| ItemHeaderContext {
                source: section.source.clone(),
                line: section.line,
                header: section.header.clone(),
                item_name: section.name.clone(),
                error_code: section.error_code.clone(),
                retry: section.retry,
            }),
    );
}

fn collect_dll_invocation_contexts(
    main_sections: &ParsedScriptSections,
    macro_sections: Option<&ParsedScriptSections>,
) -> Vec<DllInvocationContext> {
    let mut contexts = Vec::new();
    append_dll_invocation_contexts(main_sections, &mut contexts);
    if let Some(sections) = macro_sections {
        append_dll_invocation_contexts(sections, &mut contexts);
    }
    contexts
}

fn append_dll_invocation_contexts(
    sections: &ParsedScriptSections,
    contexts: &mut Vec<DllInvocationContext>,
) {
    for section in &sections.sections {
        contexts.extend(
            section
                .rows
                .iter()
                .filter(|row| !row.dll_suffixes.is_empty())
                .map(|row| DllInvocationContext {
                    source: section.source.clone(),
                    line: row.line,
                    item_name: section.name.clone(),
                    row_label: row.label.clone(),
                    dll_name: row.dll_name.clone(),
                    dll_base_name: row.dll_base_name.clone(),
                    dll_suffixes: row.dll_suffixes.clone(),
                    dll_invocation_mode: row.dll_invocation_mode.clone(),
                    dll_function: row.dll_function.clone(),
                    evidence: row.raw.clone(),
                }),
        );
    }
}

fn data_entry_value(
    data_sections: &[DataSection],
    section_name: &str,
    key: &str,
) -> Option<String> {
    matching_data_sections(data_sections, section_name)
        .into_iter()
        .find_map(|section| find_entry(section, key).map(|entry| entry.value.clone()))
}

fn collect_ini_sources(
    request: &AnalysisRequest,
    main_flow_path: &Path,
    macro_list_path: Option<&Path>,
) -> Result<Vec<SourceFile>, String> {
    let Some(root) = request
        .scripts_root
        .as_deref()
        .or_else(|| main_flow_path.parent())
    else {
        return Ok(Vec::new());
    };
    if !root.is_dir() {
        return Ok(Vec::new());
    }

    let main_name = main_flow_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("MAIN_FLOW.ini")
        .to_ascii_lowercase();
    let macro_name = macro_list_path
        .and_then(|path| path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("MACRO_LIST.ini")
        .to_ascii_lowercase();

    let mut paths = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|error| format!("failed to read {}: {error}", root.display()))?
    {
        let entry =
            entry.map_err(|error| format!("failed to read {} entry: {error}", root.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !extension.eq_ignore_ascii_case("ini") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if file_name == main_name || file_name == macro_name {
            continue;
        }
        paths.push(path);
    }
    paths.extend(collect_runtime_variable_paths(root)?);
    paths.sort_by_key(|path| data_source_sort_key(path));

    let mut sources = Vec::new();
    for path in paths {
        sources.push(SourceFile {
            name: runtime_source_name(root, &path),
            text: read_text_lossy(&path)?,
        });
    }
    Ok(sources)
}

fn collect_runtime_variable_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut candidates = BTreeSet::new();
    candidates.insert(root.join("Temp"));
    if let Some(program_root) = root.parent() {
        candidates.insert(program_root.join("Temp"));
    }

    let mut paths = Vec::new();
    for temp_root in candidates {
        if !temp_root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&temp_root)
            .map_err(|error| format!("failed to read {}: {error}", temp_root.display()))?
        {
            let entry = entry.map_err(|error| {
                format!("failed to read {} entry: {error}", temp_root.display())
            })?;
            let process_dir = entry.path();
            if !process_dir.is_dir() || !is_numeric_process_dir(&process_dir) {
                continue;
            }
            let path = process_dir.join("VarTemp_DontUseInDll.ini");
            if path.is_file() {
                paths.push(path);
            }
        }
    }
    paths.sort_by_key(|path| runtime_process_sort_key(path));
    Ok(paths)
}

fn is_numeric_process_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| !name.is_empty() && name.chars().all(|ch| ch.is_ascii_digit()))
}

fn runtime_process_sort_key(path: &Path) -> (u32, String) {
    let process = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    (process, path_string(path))
}

fn data_source_sort_key(path: &Path) -> (u8, u32, String) {
    if file_name(path).eq_ignore_ascii_case("VarTemp_DontUseInDll.ini") {
        let (process, path) = runtime_process_sort_key(path);
        return (1, process, path);
    }
    (0, 0, file_name(path))
}

fn runtime_source_name(root: &Path, path: &Path) -> String {
    if file_name(path).eq_ignore_ascii_case("VarTemp_DontUseInDll.ini") {
        if let Some(program_root) = root.parent() {
            if let Ok(relative) = path.strip_prefix(program_root) {
                return path_string(relative);
            }
        }
    }
    file_name(path)
}

fn collect_variable_references(
    main_sections: &ParsedScriptSections,
    macro_sections: Option<&ParsedScriptSections>,
    data_sections: &[DataSection],
    runtime_variables: &RuntimeVariableSources,
) -> Vec<VariableReference> {
    let mut references = Vec::new();
    collect_section_variable_references(
        main_sections,
        data_sections,
        runtime_variables,
        &mut references,
    );
    if let Some(macros) = macro_sections {
        collect_section_variable_references(
            macros,
            data_sections,
            runtime_variables,
            &mut references,
        );
    }
    references
}

fn collect_runtime_variable_sources(
    main_sections: &ParsedScriptSections,
    macro_sections: Option<&ParsedScriptSections>,
) -> RuntimeVariableSources {
    let mut runtime_variables = RuntimeVariableSources::default();
    append_runtime_variable_sources(main_sections, &mut runtime_variables);
    if let Some(macros) = macro_sections {
        append_runtime_variable_sources(macros, &mut runtime_variables);
    }
    runtime_variables
}

fn append_runtime_variable_sources(
    parsed: &ParsedScriptSections,
    runtime_variables: &mut RuntimeVariableSources,
) {
    for section in &parsed.sections {
        for row in &section.rows {
            if case_key(&row.dll_function) == "sfis_to_var" {
                for name in runtime_sfis_variable_names(&row.criteria) {
                    runtime_variables.insert_section(&name, &section.source, row.line);
                }
            }
            if case_key(&row.dll_function) == "record_testresult"
                && has_named_parameter(&row.criteria, "RECORD_TIMES")
            {
                if let Some(header) = runtime_dll_variable_header(row) {
                    runtime_variables.insert_key(
                        &header,
                        "RECORD_TIMES",
                        &section.source,
                        row.line,
                    );
                }
            }
        }
    }
}

fn runtime_sfis_variable_names(criteria: &str) -> Vec<String> {
    criteria
        .split(['&', ',', ';'])
        .map(|value| value.trim())
        .filter(|value| {
            !value.is_empty()
                && !value.eq_ignore_ascii_case("NULL")
                && !value.contains('=')
                && find_variable_prefix(value).is_none()
        })
        .map(ToString::to_string)
        .collect()
}

fn has_named_parameter(value: &str, name: &str) -> bool {
    let requested = case_key(name);
    value.split(['&', ';', ',']).any(|part| {
        part.split_once('=')
            .map(|(key, _)| case_key(key.trim()) == requested)
            .unwrap_or(false)
    })
}

fn runtime_dll_variable_header(row: &ScriptRow) -> Option<String> {
    let dll_name = row.dll_base_name.trim();
    let Some(rest) = dll_name.strip_prefix("DLL") else {
        return None;
    };
    let rest = rest.trim_start_matches('_');
    if rest.is_empty() {
        return None;
    }
    Some(format!("DLL_{rest}"))
}

fn collect_section_variable_references(
    parsed: &ParsedScriptSections,
    data_sections: &[DataSection],
    runtime_variables: &RuntimeVariableSources,
    references: &mut Vec<VariableReference>,
) {
    for section in &parsed.sections {
        for row in &section.rows {
            for token in extract_variable_tokens(&row.raw_value) {
                references.push(resolve_variable_reference(
                    &section.source,
                    row.line,
                    &row.label,
                    &token,
                    &row.raw,
                    data_sections,
                    runtime_variables,
                ));
            }
        }
    }
}

fn extract_variable_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut search_start = 0;
    while let Some((relative_start, prefix)) = find_variable_prefix(&value[search_start..]) {
        let start = search_start + relative_start;
        let mut cursor = start + prefix.len();
        let mut depth = 1usize;
        let mut found_end = None;
        while cursor < value.len() {
            if let Some((0, nested_prefix)) = find_variable_prefix(&value[cursor..]) {
                depth += 1;
                cursor += nested_prefix.len();
                continue;
            }
            let Some(ch) = value[cursor..].chars().next() else {
                break;
            };
            if ch == '#' {
                depth -= 1;
                if depth == 0 {
                    found_end = Some(cursor + ch.len_utf8());
                    break;
                }
            }
            cursor += ch.len_utf8();
        }
        let Some(end) = found_end else {
            break;
        };
        tokens.push(value[start..end].to_string());
        search_start = end;
    }
    tokens
}

fn find_variable_prefix(value: &str) -> Option<(usize, &'static str)> {
    ["*V:", "*E:", "*T:"]
        .into_iter()
        .filter_map(|prefix| value.find(prefix).map(|index| (index, prefix)))
        .min_by_key(|(index, _)| *index)
}

fn variable_key(header: &str, key: &str) -> String {
    case_key(&format!("{}-{}", header.trim(), key.trim()))
}

fn resolve_variable_reference(
    source: &str,
    line: usize,
    row_label: &str,
    token: &str,
    evidence: &str,
    data_sections: &[DataSection],
    runtime_variables: &RuntimeVariableSources,
) -> VariableReference {
    let spec = token
        .strip_prefix("*V:")
        .or_else(|| token.strip_prefix("*E:"))
        .or_else(|| token.strip_prefix("*T:"))
        .and_then(|value| value.strip_suffix('#'))
        .unwrap_or_default();
    if spec.is_empty() {
        return variable_reference(
            source,
            line,
            row_label,
            token,
            "",
            None,
            "malformed",
            "malformed",
            None,
            None,
            None,
            evidence,
        );
    }
    if find_variable_prefix(spec).is_some() {
        return variable_reference(
            source, line, row_label, token, spec, None, "dynamic", "dynamic", None, None, None,
            evidence,
        );
    }

    if let Some((header, key)) = spec.split_once('-') {
        let header = header.trim();
        let key = key.trim();
        if header.is_empty() || key.is_empty() {
            return variable_reference(
                source,
                line,
                row_label,
                token,
                header,
                Some(key.to_string()),
                "key",
                "malformed",
                None,
                None,
                None,
                evidence,
            );
        }
        if let Some(origin) = runtime_variables.key_origin(header, key) {
            return variable_reference(
                source,
                line,
                row_label,
                token,
                header,
                Some(key.to_string()),
                "key",
                "dynamic",
                None,
                Some(origin.source.clone()),
                Some(origin.line),
                evidence,
            );
        }
        let matches = matching_data_sections(data_sections, header);
        if matches.is_empty() {
            return variable_reference(
                source,
                line,
                row_label,
                token,
                header,
                Some(key.to_string()),
                "key",
                "unresolved_header",
                None,
                None,
                None,
                evidence,
            );
        }
        for section in matches {
            if let Some(entry) = find_entry(section, key) {
                return variable_reference(
                    source,
                    line,
                    row_label,
                    token,
                    header,
                    Some(key.to_string()),
                    "key",
                    "resolved",
                    Some(entry.value.clone()),
                    Some(section.source.clone()),
                    Some(entry.line),
                    evidence,
                );
            }
        }
        return variable_reference(
            source,
            line,
            row_label,
            token,
            header,
            Some(key.to_string()),
            "key",
            "unresolved_key",
            None,
            None,
            None,
            evidence,
        );
    }

    let header = spec.trim();
    let Some(section) = matching_data_sections(data_sections, header)
        .into_iter()
        .next()
    else {
        if let Some(origin) = runtime_variables.section_origin(header) {
            return variable_reference(
                source,
                line,
                row_label,
                token,
                header,
                None,
                "section",
                "dynamic",
                None,
                Some(origin.source.clone()),
                Some(origin.line),
                evidence,
            );
        }
        return variable_reference(
            source,
            line,
            row_label,
            token,
            header,
            None,
            "section",
            "unresolved_header",
            None,
            None,
            None,
            evidence,
        );
    };
    let value = section_variable_value(header, section);
    variable_reference(
        source,
        line,
        row_label,
        token,
        header,
        None,
        "section",
        "resolved",
        Some(value),
        Some(section.source.clone()),
        Some(section.line),
        evidence,
    )
}

#[allow(clippy::too_many_arguments)]
fn variable_reference(
    source: &str,
    line: usize,
    row_label: &str,
    token: &str,
    header: &str,
    key: Option<String>,
    kind: &str,
    status: &str,
    resolved_value: Option<String>,
    value_source: Option<String>,
    value_line: Option<usize>,
    evidence: &str,
) -> VariableReference {
    VariableReference {
        source: source.to_string(),
        line,
        row_label: row_label.to_string(),
        token: token.to_string(),
        header: header.to_string(),
        key,
        kind: kind.to_string(),
        status: status.to_string(),
        resolved_value,
        value_source,
        value_line,
        evidence: evidence.to_string(),
    }
}

fn matching_data_sections<'a>(
    data_sections: &'a [DataSection],
    header: &str,
) -> Vec<&'a DataSection> {
    let requested = case_key(header);
    let exact: Vec<&DataSection> = data_sections
        .iter()
        .filter(|section| case_key(&section.name) == requested)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let suffix: Vec<&DataSection> = data_sections
        .iter()
        .filter(|section| case_key(section_suffix_name(&section.name)) == requested)
        .collect();
    if !suffix.is_empty() {
        return suffix;
    }
    data_sections
        .iter()
        .filter(|section| case_key(section_base_name(&section.name)) == requested)
        .collect()
}

fn section_base_name(name: &str) -> &str {
    name.split_once(':')
        .map(|(base, _)| base.trim())
        .unwrap_or(name.trim())
}

fn section_suffix_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, suffix)| suffix.trim())
        .unwrap_or(name.trim())
}

fn find_entry<'a>(section: &'a DataSection, key: &str) -> Option<&'a DataEntry> {
    let requested = case_key(key);
    let prefixed = prefixed_entry_keys(section, key)
        .into_iter()
        .map(|value| case_key(&value))
        .collect::<Vec<_>>();
    section.entries.iter().find(|entry| {
        let entry_key = case_key(&entry.key);
        entry_key == requested || prefixed.iter().any(|key| key == &entry_key)
    })
}

fn prefixed_entry_keys(section: &DataSection, key: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    prefixes.push(section.name.trim());
    prefixes.push(section_suffix_name(&section.name));
    prefixes.push(section_base_name(&section.name));

    let mut values = Vec::new();
    let mut seen = HashSet::new();
    for prefix in prefixes {
        if prefix.is_empty() {
            continue;
        }
        let candidate = format!("{prefix}-{key}");
        if seen.insert(case_key(&candidate)) {
            values.push(candidate);
        }
    }
    values
}

fn section_variable_value(header: &str, section: &DataSection) -> String {
    section
        .entries
        .iter()
        .map(|entry| format!("{}-{}={}", header, entry.key, entry.value))
        .collect::<Vec<_>>()
        .join("&")
}

fn collect_data_sections(parsed: &ParsedScriptSections) -> Vec<DataSection> {
    parsed
        .sections
        .iter()
        .filter(|section| !section.data_entries.is_empty())
        .map(|section| DataSection {
            source: section.source.clone(),
            name: section.name.clone(),
            display_name: section.display_name.clone(),
            header: section.header.clone(),
            line: section.line,
            entries: section.data_entries.clone(),
        })
        .collect()
}

fn resolve_main_flow(request: &AnalysisRequest) -> Result<PathBuf, String> {
    if let Some(path) = request.main_flow.as_ref() {
        return Ok(path.clone());
    }
    if let Some(root) = request.scripts_root.as_ref() {
        return Ok(root.join("MAIN_FLOW.ini"));
    }
    Err("provide --main-flow or --scripts-root".to_string())
}

fn resolve_macro_list(request: &AnalysisRequest) -> Option<PathBuf> {
    request.macro_list.clone().or_else(|| {
        request
            .scripts_root
            .as_ref()
            .map(|root| root.join("MACRO_LIST.ini"))
            .filter(|path| path.exists())
    })
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

fn validate_flows(
    flows: &[Flow],
    main_sections: &ParsedScriptSections,
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let section_names: HashSet<String> = main_sections
        .sections
        .iter()
        .map(|section| case_key(&section.name))
        .collect();
    for flow in flows {
        for row in &flow.rows {
            let item = &row.item;
            if !section_names.contains(&case_key(item)) {
                diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    "FLOW_ITEM_SECTION_MISSING",
                    source_name,
                    row.line,
                    format!(
                        "{} FLOW item '{item}' has no matching implementation section.",
                        flow.kind.as_str()
                    ),
                    item,
                ));
            }
        }
    }
}

fn validate_branch_targets(parsed: &ParsedScriptSections, diagnostics: &mut Vec<Diagnostic>) {
    for section in &parsed.sections {
        let labels: HashSet<String> = section
            .rows
            .iter()
            .map(|row| case_key(&label_without_retry(&row.label)))
            .collect();
        for row in &section.rows {
            for (field_name, token) in [("PassPath", &row.pass_path), ("FailPath", &row.fail_path)]
            {
                let trimmed = token.trim();
                if trimmed.eq_ignore_ascii_case("NEXT") || is_terminal_token(trimmed) {
                    continue;
                }
                if !labels.contains(&case_key(&label_without_retry(trimmed))) {
                    diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        "BRANCH_TARGET_MISSING",
                        &section.source,
                        row.line,
                        format!(
                            "{field_name} target '{trimmed}' is not defined in section '{}'.",
                            section.display_name
                        ),
                        &row.raw,
                    ));
                }
            }
        }
    }
}

fn validate_macro_calls(
    main_sections: &ParsedScriptSections,
    macro_sections: &ParsedScriptSections,
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let macro_names: HashSet<String> = macro_sections
        .sections
        .iter()
        .map(|section| case_key(&section.name))
        .collect();
    for row in main_sections
        .sections
        .iter()
        .flat_map(|section| &section.rows)
    {
        if row.dll_name.trim().eq_ignore_ascii_case("MACRO")
            && !macro_names.contains(&case_key(&row.dll_function))
        {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "MACRO_TARGET_MISSING",
                source_name,
                row.line,
                format!(
                    "MAIN_FLOW macro target '{}' is not defined in MACRO_LIST.ini.",
                    row.dll_function
                ),
                &row.raw,
            ));
        }
    }
}

fn select_flow<'a>(
    flows: &'a [Flow],
    requested: Option<&str>,
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<&'a Flow> {
    let test_flows: Vec<&Flow> = flows
        .iter()
        .filter(|flow| flow.kind == FlowKind::Test)
        .collect();
    if let Some(header) = requested {
        if let Some(flow) = test_flows
            .iter()
            .copied()
            .find(|flow| flow.header == header)
        {
            return Some(flow);
        }
        let target = canonical_header(header);
        if let Some(flow) = test_flows
            .iter()
            .copied()
            .find(|flow| canonical_header(&flow.header) == target)
        {
            return Some(flow);
        }
        diagnostics.push(Diagnostic::new(
            Severity::Error,
            "FLOW_HEADER_NOT_FOUND",
            source_name,
            0,
            format!("No TEST FLOW section matched: {header}"),
            header,
        ));
        return None;
    }

    match test_flows.as_slice() {
        [flow] => Some(*flow),
        [] => {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "FLOW_HEADER_NOT_FOUND",
                source_name,
                0,
                "No TEST FLOW sections were found.",
                "",
            ));
            None
        }
        many => {
            let choices = many
                .iter()
                .map(|flow| flow.header.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "FLOW_SELECTION_REQUIRED",
                source_name,
                0,
                format!("Multiple TEST FLOW sections found; choose one with --flow-header. Choices: {choices}"),
                choices,
            ));
            None
        }
    }
}

pub fn section_lookup(sections: &[ScriptSection]) -> HashMap<String, &ScriptSection> {
    sections
        .iter()
        .map(|section| (case_key(&section.name), section))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn reports_missing_branch_target() {
        let temp =
            std::env::temp_dir().join(format!("script-flow-checker-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("MAIN_FLOW.ini"),
            "[TEST FLOW:Demo]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|FUNC|NULL|NULL|1|MISSING|FAIL\"\n",
        )
        .unwrap();

        let output = analyze(AnalysisRequest {
            scripts_root: Some(temp.clone()),
            main_flow: None,
            macro_list: None,
            flow_header: None,
        })
        .unwrap();
        assert!(
            output
                .diagnostics
                .iter()
                .any(|item| item.code == "BRANCH_TARGET_MISSING")
        );
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn allows_optional_init_final_flows_and_checks_their_items() {
        let temp = std::env::temp_dir().join(format!(
            "script-flow-checker-flow-name-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("MAIN_FLOW.ini"),
            "[INIT FLOW:Typo_Init]\nBOOT = \"MISSING_INIT\"\n[TEST FLOW:Demo#SKU:X1]\nRUN = \"RUN\"\n[FINAL FLOW:Typo_Final]\nCLEANUP = \"MISSING_FINAL\"\n[RUN]\nA = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n",
        )
        .unwrap();

        let output = analyze(AnalysisRequest {
            scripts_root: Some(temp.clone()),
            main_flow: None,
            macro_list: None,
            flow_header: Some("[TEST FLOW:Demo#SKU:X1]".to_string()),
        })
        .unwrap();
        assert!(!output.diagnostics.iter().any(|item| matches!(
            item.code.as_str(),
            "INIT_FLOW_MISSING" | "FINAL_FLOW_MISSING" | "INIT_FLOW_ORPHAN" | "FINAL_FLOW_ORPHAN"
        )));
        let missing_items: Vec<&Diagnostic> = output
            .diagnostics
            .iter()
            .filter(|item| item.code == "FLOW_ITEM_SECTION_MISSING")
            .collect();
        assert_eq!(missing_items.len(), 2);
        assert!(
            missing_items
                .iter()
                .any(|item| item.message.contains("INIT FLOW item 'MISSING_INIT'"))
        );
        assert!(
            missing_items
                .iter()
                .any(|item| item.message.contains("FINAL FLOW item 'MISSING_FINAL'"))
        );
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn resolves_static_variable_references_from_ini_files() {
        let temp = std::env::temp_dir().join(format!(
            "script-flow-checker-variable-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("MAIN_FLOW.ini"),
            "[TEST_PROGRAM_VER]\nSCRIPT_VERSION = \"HH5K_Wireless_2\"\nPROGRAM_VERSION = \"2.67.9608.29119\"\n[Script_Info]\nVer = \"HH5K_Wireless_2_260616\"\n[INFORMATION]\nMODEL_NAME = HH5K\n[TEST FLOW:Demo]\nRUN = \"RUN\"\n[RUN#ErrCode:Run_fail,Retry:2]\nA = \"DLLQSPR#QUICK|FUNC|PATH_LOSS_NAME=*V:WIFI_PATHLOSS_6G-PATH_LOSS_NAME#|*V:IQ_INFO#|NULL|QUIT|FAIL\"\n",
        )
        .unwrap();
        fs::write(
            temp.join("RD_SETTING.ini"),
            "[WIFI_PATHLOSS_6G]\nPATH_LOSS_NAME=Pathloss_WiFi_6G.csv\n",
        )
        .unwrap();
        fs::write(
            temp.join("FACTORY_SETTING.ini"),
            "[IQ_INFO]\nTESTER_TYPE = \"IQTYPE_XEL_M8X\"\nREQUEST_TIMEOUT = 60\n",
        )
        .unwrap();

        let output = analyze(AnalysisRequest {
            scripts_root: Some(temp.clone()),
            main_flow: None,
            macro_list: None,
            flow_header: None,
        })
        .unwrap();

        assert!(
            !output
                .diagnostics
                .iter()
                .any(|item| item.code == "WAIT_TIME_NOT_INTEGER")
        );
        let path_loss = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:WIFI_PATHLOSS_6G-PATH_LOSS_NAME#")
            .unwrap();
        assert_eq!(path_loss.status, "resolved");
        assert_eq!(
            path_loss.resolved_value.as_deref(),
            Some("Pathloss_WiFi_6G.csv")
        );

        let iq_info = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:IQ_INFO#")
            .unwrap();
        assert_eq!(iq_info.status, "resolved");
        let resolved = iq_info.resolved_value.as_deref().unwrap();
        assert!(resolved.contains("IQ_INFO-TESTER_TYPE=IQTYPE_XEL_M8X"));
        assert!(resolved.contains("IQ_INFO-REQUEST_TIMEOUT=60"));
        assert_eq!(
            output.script_info.script_version.as_deref(),
            Some("HH5K_Wireless_2")
        );
        assert_eq!(
            output.script_info.program_version.as_deref(),
            Some("2.67.9608.29119")
        );
        assert_eq!(
            output.script_info.ver.as_deref(),
            Some("HH5K_Wireless_2_260616")
        );
        assert_eq!(output.script_info.model_name.as_deref(), Some("HH5K"));
        assert_eq!(output.item_headers.len(), 1);
        assert_eq!(output.item_headers[0].item_name, "RUN");
        assert_eq!(
            output.item_headers[0].error_code.as_deref(),
            Some("Run_fail")
        );
        assert_eq!(output.item_headers[0].retry, Some(2));
        assert_eq!(output.dll_invocations.len(), 1);
        assert_eq!(output.dll_invocations[0].dll_name, "DLLQSPR#QUICK");
        assert_eq!(output.dll_invocations[0].dll_base_name, "DLLQSPR");
        assert_eq!(output.dll_invocations[0].dll_suffixes, vec!["QUICK"]);
        assert_eq!(output.dll_invocations[0].dll_invocation_mode, "quick");
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn resolves_runtime_variables_from_vartemp_process_folder() {
        let temp = std::env::temp_dir().join(format!(
            "script-checker-vartemp-variable-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp);
        let scripts = temp.join("Scripts");
        let process = temp.join("Temp").join("1");
        fs::create_dir_all(&scripts).unwrap();
        fs::create_dir_all(&process).unwrap();
        fs::write(
            scripts.join("MAIN_FLOW.ini"),
            "[TEST FLOW:Demo]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|FUNC|DUT=*V:Setting-DUT_IP#;ISN=*E:Label-ISN#|*T:IQ_INFO#|1|MAKE_GOLDEN|FAIL\"\nMAKE_GOLDEN = \"Test Program|SFIS_TO_VAR|GOLDEN|NULL|1|RECORD_GOLDEN|FAIL\"\nRECORD_GOLDEN = \"DLLGoldenKV|RECORD_TESTRESULT|RECORD_TIMES=1&*V:GOLDEN#|NULL|1|MAKE_TEST|FAIL\"\nMAKE_TEST = \"Test Program|SFIS_TO_VAR|Test|NULL|1|RECORD_TEST|FAIL\"\nRECORD_TEST = \"DLLGoldenKV|RECORD_TESTRESULT|RECORD_TIMES=1&*V:Test#|NULL|1|CHECK_TIMES|FAIL\"\nCHECK_TIMES = \"Test Program|LABEL_COMPARE|CHECK_RECORD_TIMES,*V:DLL_GoldenKV-RECORD_TIMES#|RECORD_TIMES,1|1|QUIT|FAIL\"\n",
        )
        .unwrap();
        fs::write(
            process.join("VarTemp_DontUseInDll.ini"),
            "[Label]\nLabel-ISN=DM2400162000000\n[FACTORY_SETTING:Setting]\nSetting-DUT_IP=192.168.5.1\n[FACTORY_SETTING:IQ_INFO]\nIQ_INFO-IP_ADDRESS=192.168.100.254\n",
        )
        .unwrap();

        let output = analyze(AnalysisRequest {
            scripts_root: Some(scripts.clone()),
            main_flow: None,
            macro_list: None,
            flow_header: None,
        })
        .unwrap();

        let dut_ip = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:Setting-DUT_IP#")
            .unwrap();
        assert_eq!(dut_ip.status, "resolved");
        assert_eq!(dut_ip.resolved_value.as_deref(), Some("192.168.5.1"));
        assert_eq!(
            dut_ip.value_source.as_deref(),
            Some("Temp\\1\\VarTemp_DontUseInDll.ini")
        );

        let isn = output
            .variable_references
            .iter()
            .find(|item| item.token == "*E:Label-ISN#")
            .unwrap();
        assert_eq!(isn.status, "resolved");
        assert_eq!(isn.resolved_value.as_deref(), Some("DM2400162000000"));

        let iq_info = output
            .variable_references
            .iter()
            .find(|item| item.token == "*T:IQ_INFO#")
            .unwrap();
        assert_eq!(iq_info.status, "resolved");
        assert!(
            iq_info
                .resolved_value
                .as_deref()
                .unwrap()
                .contains("IQ_INFO-IP_ADDRESS=192.168.100.254")
        );

        let golden = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:GOLDEN#")
            .unwrap();
        assert_eq!(golden.status, "dynamic");
        assert_eq!(golden.value_source.as_deref(), Some("MAIN_FLOW.ini"));

        let test = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:Test#")
            .unwrap();
        assert_eq!(test.status, "dynamic");
        assert_eq!(test.value_source.as_deref(), Some("MAIN_FLOW.ini"));

        let record_times = output
            .variable_references
            .iter()
            .find(|item| item.token == "*V:DLL_GoldenKV-RECORD_TIMES#")
            .unwrap();
        assert_eq!(record_times.status, "dynamic");
        assert_eq!(record_times.value_source.as_deref(), Some("MAIN_FLOW.ini"));

        let _ = fs::remove_dir_all(&temp);
    }
}
