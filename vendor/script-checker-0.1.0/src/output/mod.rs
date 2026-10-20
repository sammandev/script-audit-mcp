use std::collections::BTreeMap;

use crate::analysis::AnalysisOutput;
use crate::diagnostics::{Diagnostic, RelatedLocation};
use crate::graph::{GraphEdge, GraphIssue, GraphNode, GraphSegment, ScriptFlowGraph};
use crate::models::{
    DataEntry, DataSection, DllInvocationContext, Flow, FlowKind, FlowRow, ItemHeaderContext,
    ScriptInfo, VariableReference,
};

mod xlsx;

pub use xlsx::{render_analysis_xlsx, render_batch_summary_xlsx, render_list_flows_xlsx};

#[derive(Debug, Clone)]
pub struct BatchRunSummary {
    pub created_at: String,
    pub tool_name: String,
    pub tool_version: String,
    pub scripts_root: String,
    pub output_root: String,
    pub script_info: ScriptInfo,
    pub checked_flows: usize,
    pub reported_flows: usize,
    pub status: BTreeMap<String, usize>,
    pub results: Vec<BatchRunResult>,
    pub diagnostics: Vec<BatchDiagnosticSummary>,
}

#[derive(Debug, Clone)]
pub struct BatchRunResult {
    pub created_at: String,
    pub header: String,
    pub status: String,
    pub errors: usize,
    pub warnings: usize,
    pub path_issues: usize,
    pub json_path: String,
    pub text_path: String,
}

#[derive(Debug, Clone)]
pub struct BatchDiagnosticSummary {
    pub severity: String,
    pub code: String,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub evidence: String,
}

pub fn render_json(output: &AnalysisOutput, include_graph: bool) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    field_str(&mut out, 1, "schema_version", &output.schema_version, true);
    field_str(&mut out, 1, "created_at", &output.created_at, true);
    out.push_str(&format!(
        "  \"tool\": {{ \"name\": {}, \"version\": {} }},\n",
        q(&output.tool.name),
        q(&output.tool.version)
    ));
    field_str(&mut out, 1, "status", &output.status, true);
    out.push_str("  \"inputs\": {\n");
    field_opt_str(
        &mut out,
        2,
        "script_root",
        output.inputs.script_root.as_deref(),
        true,
    );
    field_opt_str(
        &mut out,
        2,
        "main_flow",
        output.inputs.main_flow.as_deref(),
        true,
    );
    field_opt_str(
        &mut out,
        2,
        "macro_list",
        output.inputs.macro_list.as_deref(),
        true,
    );
    field_opt_str(
        &mut out,
        2,
        "flow_header",
        output.inputs.flow_header.as_deref(),
        false,
    );
    out.push_str("  },\n");
    out.push_str("  \"script_info\": ");
    write_script_info(&mut out, &output.script_info, 1);
    out.push_str(",\n");
    out.push_str("  \"counts\": {\n");
    field_usize(&mut out, 2, "errors", output.counts.errors, true);
    field_usize(&mut out, 2, "warnings", output.counts.warnings, true);
    field_usize(&mut out, 2, "flows", output.counts.flows, true);
    field_usize(&mut out, 2, "items", output.counts.items, true);
    field_usize(&mut out, 2, "sections", output.counts.sections, true);
    field_usize(&mut out, 2, "nodes", output.counts.nodes, true);
    field_usize(&mut out, 2, "edges", output.counts.edges, true);
    field_usize(&mut out, 2, "issues", output.counts.issues, true);
    field_usize(
        &mut out,
        2,
        "data_sections",
        output.counts.data_sections,
        true,
    );
    field_usize(
        &mut out,
        2,
        "data_entries",
        output.counts.data_entries,
        true,
    );
    field_usize(
        &mut out,
        2,
        "variable_references",
        output.counts.variable_references,
        true,
    );
    field_usize(
        &mut out,
        2,
        "variables_resolved",
        output.counts.variables_resolved,
        true,
    );
    field_usize(
        &mut out,
        2,
        "variables_unresolved",
        output.counts.variables_unresolved,
        true,
    );
    field_usize(
        &mut out,
        2,
        "variables_dynamic",
        output.counts.variables_dynamic,
        false,
    );
    out.push_str("  },\n");
    out.push_str("  \"flows\": ");
    write_flow_array(&mut out, &output.flows, 1);
    out.push_str(",\n  \"item_headers\": ");
    write_item_header_context_array(&mut out, &output.item_headers, 1);
    out.push_str(",\n  \"dll_invocations\": ");
    write_dll_invocation_context_array(&mut out, &output.dll_invocations, 1);
    out.push_str(",\n  \"data_sections\": ");
    write_data_section_array(&mut out, &output.data_sections, 1);
    out.push_str(",\n  \"variable_references\": ");
    write_variable_reference_array(&mut out, &output.variable_references, 1);
    out.push_str(",\n  \"diagnostics\": ");
    write_diagnostic_array(&mut out, &output.diagnostics, 1);
    out.push_str(",\n  \"path_checks\": ");
    write_path_checks(&mut out, output.graph.as_ref(), 1);
    out.push_str(",\n  \"path_issues\": ");
    if let Some(graph) = &output.graph {
        write_issue_array(&mut out, &graph.issues, 1);
    } else {
        out.push_str("[]");
    }
    out.push_str(",\n  \"graph\": ");
    if let Some(graph) = &output.graph {
        if include_graph {
            write_graph(&mut out, graph, 1);
        } else {
            write_graph_summary(&mut out, graph, 1);
        }
    } else {
        out.push_str("null");
    }
    out.push_str("\n}\n");
    out
}

pub fn render_list_flows_json(headers: &[String]) -> String {
    let mut out = String::new();
    out.push_str("{\n  \"flow_headers\": ");
    write_string_array(&mut out, headers, 1);
    out.push_str("\n}\n");
    out
}

pub fn render_batch_summary_json(summary: &BatchRunSummary) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    field_str(&mut out, 1, "created_at", &summary.created_at, true);
    out.push_str(&format!(
        "  \"tool\": {{ \"name\": {}, \"version\": {} }},\n",
        q(&summary.tool_name),
        q(&summary.tool_version)
    ));
    field_str(&mut out, 1, "scripts_root", &summary.scripts_root, true);
    field_str(&mut out, 1, "output_root", &summary.output_root, true);
    out.push_str("  \"script_info\": ");
    write_script_info(&mut out, &summary.script_info, 1);
    out.push_str(",\n");
    out.push_str("  \"summary\": {\n");
    field_usize(&mut out, 2, "checked_flows", summary.checked_flows, true);
    field_usize(&mut out, 2, "reported_flows", summary.reported_flows, true);
    ind(&mut out, 2);
    out.push_str("\"status\": ");
    write_status_map(&mut out, &summary.status, 2);
    out.push('\n');
    out.push_str("  },\n");
    ind(&mut out, 1);
    out.push_str("\"results\": ");
    write_batch_result_array(&mut out, &summary.results, 1);
    out.push_str(",\n");
    ind(&mut out, 1);
    out.push_str("\"diagnostics\": ");
    write_batch_diagnostic_array(&mut out, &summary.diagnostics, 1);
    out.push('\n');
    out.push_str("}\n");
    out
}

pub fn render_batch_summary_csv(summary: &BatchRunSummary) -> String {
    let mut out = String::new();
    csv_report_header(&mut out);
    csv_key_value(&mut out, "meta", 0, "created_at", &summary.created_at);
    csv_key_value(&mut out, "meta", 0, "tool_name", &summary.tool_name);
    csv_key_value(&mut out, "meta", 0, "tool_version", &summary.tool_version);
    csv_key_value(&mut out, "meta", 0, "scripts_root", &summary.scripts_root);
    csv_key_value(&mut out, "meta", 0, "output_root", &summary.output_root);
    csv_key_value(
        &mut out,
        "meta",
        0,
        "script_version",
        opt_display(&summary.script_info.script_version),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "program_version",
        opt_display(&summary.script_info.program_version),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "ver",
        opt_display(&summary.script_info.ver),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "model_name",
        opt_display(&summary.script_info.model_name),
    );
    csv_key_value(
        &mut out,
        "summary",
        0,
        "checked_flows",
        &summary.checked_flows.to_string(),
    );
    csv_key_value(
        &mut out,
        "summary",
        0,
        "reported_flows",
        &summary.reported_flows.to_string(),
    );

    for (index, (status, count)) in summary.status.iter().enumerate() {
        csv_status_row(&mut out, index, status, *count);
    }

    for (index, row) in summary.results.iter().enumerate() {
        csv_batch_result_row(&mut out, index, row);
    }

    for (index, row) in summary.diagnostics.iter().enumerate() {
        csv_summary_diagnostic_row(&mut out, index, row);
    }
    out
}

pub fn render_csv(output: &AnalysisOutput) -> String {
    let mut out = String::new();
    csv_report_header(&mut out);
    csv_key_value(
        &mut out,
        "meta",
        0,
        "schema_version",
        &output.schema_version,
    );
    csv_key_value(&mut out, "meta", 0, "created_at", &output.created_at);
    csv_key_value(&mut out, "meta", 0, "tool_name", &output.tool.name);
    csv_key_value(&mut out, "meta", 0, "tool_version", &output.tool.version);
    csv_key_value(&mut out, "meta", 0, "status", &output.status);
    csv_key_value(
        &mut out,
        "meta",
        0,
        "script_root",
        output.inputs.script_root.as_deref().unwrap_or("-"),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "main_flow",
        output.inputs.main_flow.as_deref().unwrap_or("-"),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "macro_list",
        output.inputs.macro_list.as_deref().unwrap_or("-"),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "flow_header",
        output.inputs.flow_header.as_deref().unwrap_or("-"),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "script_version",
        opt_display(&output.script_info.script_version),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "program_version",
        opt_display(&output.script_info.program_version),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "ver",
        opt_display(&output.script_info.ver),
    );
    csv_key_value(
        &mut out,
        "meta",
        0,
        "model_name",
        opt_display(&output.script_info.model_name),
    );

    for (name, value) in count_pairs(&output.counts) {
        csv_key_value(&mut out, "count", 0, name, &value.to_string());
    }

    if let Some(graph) = &output.graph {
        csv_path_check_status_row(&mut out, &graph.status);
        csv_key_value(&mut out, "path_check", 0, "flow_header", &graph.flow_header);
        for (name, value) in path_check_pairs(graph) {
            csv_key_value(&mut out, "path_check", 0, name, &value.to_string());
        }
    }

    for (index, row) in output.diagnostics.iter().enumerate() {
        csv_analysis_diagnostic_row(&mut out, index, row);
    }

    if let Some(graph) = &output.graph {
        for (index, issue) in graph.issues.iter().enumerate() {
            csv_path_issue_row(&mut out, index, issue);
        }
    }
    out
}

pub fn render_flows_csv(headers: &[String]) -> String {
    let mut out = String::new();
    csv_row(&mut out, &["index", "flow_header"]);
    for (index, header) in headers.iter().enumerate() {
        csv_row(&mut out, &[&(index + 1).to_string(), header]);
    }
    out
}

fn count_pairs(counts: &crate::analysis::AnalysisCounts) -> Vec<(&'static str, usize)> {
    vec![
        ("errors", counts.errors),
        ("warnings", counts.warnings),
        ("flows", counts.flows),
        ("items", counts.items),
        ("sections", counts.sections),
        ("nodes", counts.nodes),
        ("edges", counts.edges),
        ("issues", counts.issues),
        ("data_sections", counts.data_sections),
        ("data_entries", counts.data_entries),
        ("variable_references", counts.variable_references),
        ("variables_resolved", counts.variables_resolved),
        ("variables_unresolved", counts.variables_unresolved),
        ("variables_dynamic", counts.variables_dynamic),
    ]
}

fn path_check_pairs(graph: &ScriptFlowGraph) -> Vec<(&'static str, usize)> {
    vec![
        ("items_checked", graph.item_count),
        ("rows_checked", graph_row_count(graph)),
        ("pass_paths", graph_edge_count(graph, "pass")),
        ("fail_paths", graph_edge_count(graph, "fail")),
        ("next_paths", graph_next_path_count(graph)),
        ("terminal_paths", graph_terminal_path_count(graph)),
        ("macro_calls", graph_edge_count(graph, "macro")),
        ("macro_returns", graph_edge_count(graph, "macro_return")),
        (
            "unresolved_paths",
            graph_issue_count(graph, "unresolved_branch_target")
                + graph_issue_count(graph, "unresolved_macro_branch_target"),
        ),
        (
            "missing_next_sections",
            graph_issue_count(graph, "missing_next_section"),
        ),
        (
            "unreachable_rows",
            graph_issue_count(graph, "unreachable_row"),
        ),
        (
            "potential_infinite_loops",
            graph_issue_count(graph, "potential_infinite_loop"),
        ),
        ("issues", graph.issues.len()),
    ]
}

fn csv_row(out: &mut String, values: &[&str]) {
    let cells: Vec<String> = values.iter().map(|value| csv_cell(value)).collect();
    out.push_str(&cells.join(","));
    out.push('\n');
}

fn csv_report_header(out: &mut String) {
    csv_row(
        out,
        &[
            "type",
            "record",
            "header",
            "status",
            "errors",
            "warnings",
            "path_issues",
            "json_path",
            "text_path",
            "severity",
            "code",
            "file",
            "line",
            "message",
            "evidence",
            "key",
            "value",
        ],
    );
}

fn csv_key_value(out: &mut String, row_type: &str, record: usize, key: &str, value: &str) {
    let record = record.to_string();
    csv_row(
        out,
        &[
            row_type, &record, "", "", "", "", "", "", "", "", "", "", "", "", "", key, value,
        ],
    );
}

fn csv_status_row(out: &mut String, record: usize, status: &str, count: usize) {
    let record = record.to_string();
    let count = count.to_string();
    csv_row(
        out,
        &[
            "status", &record, "", status, "", "", "", "", "", "", "", "", "", "", "", "count",
            &count,
        ],
    );
}

fn csv_path_check_status_row(out: &mut String, status: &str) {
    csv_row(
        out,
        &[
            "path_check",
            "0",
            "",
            status,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "status",
            status,
        ],
    );
}

fn csv_batch_result_row(out: &mut String, record: usize, row: &BatchRunResult) {
    let record = record.to_string();
    let errors = row.errors.to_string();
    let warnings = row.warnings.to_string();
    let path_issues = row.path_issues.to_string();
    csv_row(
        out,
        &[
            "result",
            &record,
            &row.header,
            &row.status,
            &errors,
            &warnings,
            &path_issues,
            &row.json_path,
            &row.text_path,
            "",
            "",
            "",
            "",
            "",
            "",
            "created_at",
            &row.created_at,
        ],
    );
}

fn csv_summary_diagnostic_row(out: &mut String, record: usize, row: &BatchDiagnosticSummary) {
    let record = record.to_string();
    let line = row.line.to_string();
    csv_row(
        out,
        &[
            "diagnostic",
            &record,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            &row.severity,
            &row.code,
            &row.file,
            &line,
            &row.message,
            &row.evidence,
            "",
            "",
        ],
    );
}

fn csv_analysis_diagnostic_row(out: &mut String, record: usize, row: &Diagnostic) {
    let record = record.to_string();
    let line = row.line.to_string();
    csv_row(
        out,
        &[
            "diagnostic",
            &record,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            row.severity.as_str(),
            &row.code,
            &row.file,
            &line,
            &row.message,
            &row.evidence,
            "",
            "",
        ],
    );
}

fn csv_path_issue_row(out: &mut String, record: usize, issue: &GraphIssue) {
    let record = record.to_string();
    let key = [
        ("item", issue.item.as_deref().unwrap_or("-")),
        ("label", issue.label.as_deref().unwrap_or("-")),
        ("target", issue.target.as_deref().unwrap_or("-")),
        ("detail", issue.detail.as_str()),
    ]
    .iter()
    .map(|(key, value)| format!("{key}={value}"))
    .collect::<Vec<_>>()
    .join("; ");
    csv_row(
        out,
        &[
            "path_issue",
            &record,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            &issue.issue_type,
            "",
            "",
            &issue.message,
            &issue.evidence,
            "context",
            &key,
        ],
    );
}

fn write_status_map(out: &mut String, values: &BTreeMap<String, usize>, indent: usize) {
    if values.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    let len = values.len();
    for (index, (key, value)) in values.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str(&format!(
            "{}: {}{}\n",
            q(key),
            value,
            if index + 1 < len { "," } else { "" }
        ));
    }
    ind(out, indent);
    out.push('}');
}

fn write_script_info(out: &mut String, script_info: &ScriptInfo, indent: usize) {
    out.push_str("{\n");
    field_opt_str(
        out,
        indent + 1,
        "script_version",
        script_info.script_version.as_deref(),
        true,
    );
    field_opt_str(
        out,
        indent + 1,
        "program_version",
        script_info.program_version.as_deref(),
        true,
    );
    field_opt_str(out, indent + 1, "ver", script_info.ver.as_deref(), true);
    field_opt_str(
        out,
        indent + 1,
        "model_name",
        script_info.model_name.as_deref(),
        false,
    );
    ind(out, indent);
    out.push('}');
}

fn opt_display(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}

fn write_batch_result_array(out: &mut String, rows: &[BatchRunResult], indent: usize) {
    if rows.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, row) in rows.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "created_at", &row.created_at, true);
        field_str(out, indent + 2, "header", &row.header, true);
        field_str(out, indent + 2, "status", &row.status, true);
        field_usize(out, indent + 2, "errors", row.errors, true);
        field_usize(out, indent + 2, "warnings", row.warnings, true);
        field_usize(out, indent + 2, "path_issues", row.path_issues, true);
        field_str(out, indent + 2, "json_path", &row.json_path, true);
        field_str(out, indent + 2, "text_path", &row.text_path, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < rows.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_batch_diagnostic_array(
    out: &mut String,
    diagnostics: &[BatchDiagnosticSummary],
    indent: usize,
) {
    if diagnostics.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "severity", &diagnostic.severity, true);
        field_str(out, indent + 2, "code", &diagnostic.code, true);
        field_str(out, indent + 2, "file", &diagnostic.file, true);
        field_usize(out, indent + 2, "line", diagnostic.line, true);
        field_str(out, indent + 2, "message", &diagnostic.message, true);
        field_str(out, indent + 2, "evidence", &diagnostic.evidence, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < diagnostics.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

pub fn render_text(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push(format!("script-checker {}", output.tool.version));
    lines.push(format!("Created at: {}", output.created_at));
    lines.push(String::new());
    lines.push("Input:".to_string());
    if let Some(path) = &output.inputs.main_flow {
        lines.push(format!("  MAIN_FLOW.ini: {path}"));
    }
    if let Some(path) = &output.inputs.macro_list {
        lines.push(format!("  MACRO_LIST.ini: {path}"));
    }
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("  Flow: {header}"));
    }
    lines.push(String::new());
    lines.push("Script Info:".to_string());
    lines.push(format!(
        "  SCRIPT_VERSION: {}",
        opt_display(&output.script_info.script_version)
    ));
    lines.push(format!(
        "  PROGRAM_VERSION: {}",
        opt_display(&output.script_info.program_version)
    ));
    lines.push(format!("  Ver: {}", opt_display(&output.script_info.ver)));
    lines.push(format!(
        "  MODEL_NAME: {}",
        opt_display(&output.script_info.model_name)
    ));
    lines.push(String::new());
    lines.push(format!("Result: {}", output.status.to_ascii_uppercase()));
    lines.push(String::new());
    lines.push("Counts:".to_string());
    lines.push(format!("  Errors: {}", output.counts.errors));
    lines.push(format!("  Warnings: {}", output.counts.warnings));
    lines.push(format!("  TEST FLOW sections: {}", output.counts.flows));
    lines.push(format!("  Flow items: {}", output.counts.items));
    lines.push(format!("  Sections: {}", output.counts.sections));
    lines.push(format!("  Data sections: {}", output.counts.data_sections));
    lines.push(format!("  Data entries: {}", output.counts.data_entries));
    lines.push(format!(
        "  Variable references: {}",
        output.counts.variable_references
    ));
    lines.push(format!(
        "  Variables resolved: {}",
        output.counts.variables_resolved
    ));
    lines.push(format!(
        "  Variables unresolved: {}",
        output.counts.variables_unresolved
    ));
    lines.push(format!(
        "  Variables dynamic: {}",
        output.counts.variables_dynamic
    ));
    lines.push(format!("  Nodes: {}", output.counts.nodes));
    lines.push(format!("  Edges: {}", output.counts.edges));
    lines.push(format!("  Graph issues: {}", output.counts.issues));

    if !output.item_headers.is_empty() {
        lines.push(String::new());
        lines.push("Item Header Context:".to_string());
        for item in &output.item_headers {
            lines.push(format!(
                "  {}:{} {} -> item={}, ErrCode={}, Retry={}",
                item.source,
                item.line,
                item.header,
                item.item_name,
                opt_display(&item.error_code),
                item.retry
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ));
        }
    }

    if !output.dll_invocations.is_empty() {
        lines.push(String::new());
        lines.push("DLL Invocation Suffix Context:".to_string());
        for item in &output.dll_invocations {
            lines.push(format!(
                "  {}:{} {}/{}: {} -> base={}, suffixes={}, mode={}, function={}",
                item.source,
                item.line,
                item.item_name,
                item.row_label,
                item.dll_name,
                item.dll_base_name,
                if item.dll_suffixes.is_empty() {
                    "-".to_string()
                } else {
                    item.dll_suffixes.join("+")
                },
                item.dll_invocation_mode,
                item.dll_function
            ));
        }
    }

    if !output.diagnostics.is_empty() {
        lines.push(String::new());
        lines.push("Diagnostics:".to_string());
        for diagnostic in &output.diagnostics {
            lines.push(format!(
                "  {:?} {}:{} {}",
                diagnostic.severity, diagnostic.file, diagnostic.line, diagnostic.code
            ));
            lines.push(format!("    {}", diagnostic.message));
            if !diagnostic.evidence.is_empty() {
                lines.push(format!("    Evidence: {}", diagnostic.evidence));
            }
        }
    }

    if let Some(graph) = &output.graph
        && !graph.issues.is_empty()
    {
        lines.push(String::new());
        lines.push("Graph Issues:".to_string());
        for issue in &graph.issues {
            lines.push(format!("  {}", issue.issue_type));
            lines.push(format!("    {}", issue.message));
            if !issue.evidence.is_empty() {
                lines.push(format!("    Evidence: {}", issue.evidence));
            }
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_concise(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}: {}",
        if output.status == "ok" {
            "OK"
        } else {
            "NOT CLEAN"
        },
        output.status.to_ascii_uppercase()
    ));
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("Flow: {header}"));
    }
    lines.push(format!(
        "Counts: errors={}, warnings={}, path_issues={}, nodes={}, edges={}",
        output.counts.errors,
        output.counts.warnings,
        output.counts.issues,
        output.counts.nodes,
        output.counts.edges
    ));
    push_limited_diagnostics(&mut lines, output, false, 3);
    push_limited_graph_issues(&mut lines, output, false, 3);
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_detailed(output: &AnalysisOutput) -> String {
    let mut lines = vec![render_text(output).trim_end().to_string()];
    if let Some(flow) = selected_flow(output) {
        lines.push(String::new());
        lines.push("Selected Flow Items:".to_string());
        for row in &flow.rows {
            lines.push(format!("  {}: {}", row.key, row.item));
        }
    }
    if let Some(graph) = &output.graph {
        lines.push(String::new());
        lines.push("Path Segment Detail:".to_string());
        for segment in &graph.segments {
            lines.push(format!(
                "  {}: status={}, rows={}, nodes={}, edges={}, issues={}",
                segment.item,
                segment.status,
                segment.row_count,
                segment.nodes.len(),
                segment.edges.len(),
                segment.issues.len()
            ));
            for issue in &segment.issues {
                lines.push(format!("    {}: {}", issue.issue_type, issue.message));
            }
        }
    }
    if !output.variable_references.is_empty() {
        lines.push(String::new());
        lines.push("Variable References:".to_string());
        for reference in &output.variable_references {
            lines.push(format!(
                "  {}:{} {} -> {} ({})",
                reference.source,
                reference.line,
                reference.token,
                reference
                    .resolved_value
                    .as_deref()
                    .or(reference.value_source.as_deref())
                    .unwrap_or("-"),
                reference.status
            ));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_path_summary(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push("Flow Path Summary".to_string());
    lines.push(format!("Status: {}", output.status.to_ascii_uppercase()));
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("Flow: {header}"));
    }
    push_path_counts(&mut lines, output);
    push_limited_graph_issues(&mut lines, output, true, 8);
    if !output.diagnostics.is_empty() {
        lines.push(format!(
            "Non-path diagnostics: {} error(s), {} warning(s)",
            output.counts.errors, output.counts.warnings
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_pass_fail_compact(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    if let Some(graph) = &output.graph {
        lines.push(format!(
            "Pass/Fail Paths: status={}, pass={}, fail={}, unresolved={}, issues={}",
            graph.status.to_ascii_uppercase(),
            graph_edge_count(graph, "pass"),
            graph_edge_count(graph, "fail"),
            graph_issue_count(graph, "unresolved_branch_target")
                + graph_issue_count(graph, "unresolved_macro_branch_target"),
            graph.issues.len()
        ));
    } else {
        lines.push("Pass/Fail Paths: no selected graph".to_string());
    }
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("Flow: {header}"));
    }
    push_limited_graph_issues(&mut lines, output, false, 5);
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_pass_fail_detailed(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push("Pass/Fail Path Detail".to_string());
    lines.push(format!("Status: {}", output.status.to_ascii_uppercase()));
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("Flow: {header}"));
    }
    push_path_counts(&mut lines, output);
    if let Some(graph) = &output.graph {
        lines.push(String::new());
        lines.push("Edges:".to_string());
        for edge in &graph.edges {
            lines.push(format!(
                "  {}/{} {} {} -> {} {}{}",
                edge.source_item,
                edge.source_label,
                edge.kind,
                edge.path,
                edge.target_kind,
                edge.target_item.as_deref().unwrap_or("-"),
                edge.target_label
                    .as_deref()
                    .map(|label| format!("/{label}"))
                    .unwrap_or_default()
            ));
        }
    }
    push_limited_graph_issues(&mut lines, output, true, usize::MAX);
    push_limited_diagnostics(&mut lines, output, true, usize::MAX);
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_syntax(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push("Script Syntax Check".to_string());
    lines.push(format!("Status: {}", output.status.to_ascii_uppercase()));
    if let Some(path) = &output.inputs.main_flow {
        lines.push(format!("MAIN_FLOW.ini: {path}"));
    }
    if let Some(path) = &output.inputs.macro_list {
        lines.push(format!("MACRO_LIST.ini: {path}"));
    }
    lines.push(format!(
        "Diagnostics: {} error(s), {} warning(s)",
        output.counts.errors, output.counts.warnings
    ));
    if output.diagnostics.is_empty() {
        lines.push("No parser or script-row diagnostics reported.".to_string());
    } else {
        push_limited_diagnostics(&mut lines, output, true, usize::MAX);
    }
    if output.counts.issues > 0 {
        lines.push(format!(
            "Path issues not shown in syntax view: {}. Use check-flow-paths or check-pass-fail-paths for path detail.",
            output.counts.issues
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn render_text_validation(output: &AnalysisOutput) -> String {
    let mut lines = Vec::new();
    lines.push("Script Flow Validation".to_string());
    lines.push(format!(
        "Result: {}",
        if output.status == "ok" {
            "PASS"
        } else {
            "FAIL"
        }
    ));
    if let Some(header) = &output.inputs.flow_header {
        lines.push(format!("Flow: {header}"));
    }
    lines.push(format!(
        "Summary: status={}, errors={}, warnings={}, path_issues={}",
        output.status, output.counts.errors, output.counts.warnings, output.counts.issues
    ));
    push_limited_diagnostics(&mut lines, output, false, usize::MAX);
    push_limited_graph_issues(&mut lines, output, false, usize::MAX);
    lines.push(String::new());
    lines.join("\n")
}

fn selected_flow(output: &AnalysisOutput) -> Option<&Flow> {
    let header = output.inputs.flow_header.as_deref()?;
    output.flows.iter().find(|flow| flow.header == header)
}

fn push_path_counts(lines: &mut Vec<String>, output: &AnalysisOutput) {
    if let Some(graph) = &output.graph {
        lines.push("Path Counts:".to_string());
        lines.push(format!("  Items checked: {}", graph.item_count));
        lines.push(format!("  Rows checked: {}", graph_row_count(graph)));
        lines.push(format!("  Pass paths: {}", graph_edge_count(graph, "pass")));
        lines.push(format!("  Fail paths: {}", graph_edge_count(graph, "fail")));
        lines.push(format!("  NEXT paths: {}", graph_next_path_count(graph)));
        lines.push(format!(
            "  Terminal paths: {}",
            graph_terminal_path_count(graph)
        ));
        lines.push(format!(
            "  Macro calls: {}",
            graph_edge_count(graph, "macro")
        ));
        lines.push(format!(
            "  Macro returns: {}",
            graph_edge_count(graph, "macro_return")
        ));
        lines.push(format!(
            "  Unresolved paths: {}",
            graph_issue_count(graph, "unresolved_branch_target")
                + graph_issue_count(graph, "unresolved_macro_branch_target")
        ));
        lines.push(format!(
            "  Missing NEXT sections: {}",
            graph_issue_count(graph, "missing_next_section")
        ));
        lines.push(format!(
            "  Unreachable rows: {}",
            graph_issue_count(graph, "unreachable_row")
        ));
        lines.push(format!(
            "  Potential infinite loops: {}",
            graph_issue_count(graph, "potential_infinite_loop")
        ));
        lines.push(format!("  Total issues: {}", graph.issues.len()));
    } else {
        lines.push("Path Counts: no selected graph".to_string());
    }
}

fn push_limited_diagnostics(
    lines: &mut Vec<String>,
    output: &AnalysisOutput,
    include_evidence: bool,
    limit: usize,
) {
    if output.diagnostics.is_empty() {
        return;
    }
    let shown = output.diagnostics.len().min(limit);
    lines.push(format!(
        "Diagnostics{}:",
        limit_suffix(output.diagnostics.len(), shown)
    ));
    for diagnostic in output.diagnostics.iter().take(shown) {
        lines.push(format!(
            "  {} {}:{} {} - {}",
            diagnostic.severity.as_str(),
            diagnostic.file,
            diagnostic.line,
            diagnostic.code,
            diagnostic.message
        ));
        if include_evidence && !diagnostic.evidence.is_empty() {
            lines.push(format!("    Evidence: {}", diagnostic.evidence));
        }
    }
}

fn push_limited_graph_issues(
    lines: &mut Vec<String>,
    output: &AnalysisOutput,
    include_evidence: bool,
    limit: usize,
) {
    let Some(graph) = &output.graph else {
        return;
    };
    if graph.issues.is_empty() {
        return;
    }
    let shown = graph.issues.len().min(limit);
    lines.push(format!(
        "Graph Issues{}:",
        limit_suffix(graph.issues.len(), shown)
    ));
    for issue in graph.issues.iter().take(shown) {
        lines.push(format!("  {} - {}", issue.issue_type, issue.message));
        if include_evidence && !issue.evidence.is_empty() {
            lines.push(format!("    Evidence: {}", issue.evidence));
        }
    }
}

fn limit_suffix(total: usize, shown: usize) -> String {
    if total > shown {
        format!(" (first {shown} of {total})")
    } else {
        String::new()
    }
}

fn write_item_header_context_array(
    out: &mut String,
    contexts: &[ItemHeaderContext],
    indent: usize,
) {
    if contexts.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, item) in contexts.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "source", &item.source, true);
        field_usize(out, indent + 2, "line", item.line, true);
        field_str(out, indent + 2, "header", &item.header, true);
        field_str(out, indent + 2, "item_name", &item.item_name, true);
        field_opt_str(
            out,
            indent + 2,
            "error_code",
            item.error_code.as_deref(),
            true,
        );
        field_opt_u32(out, indent + 2, "retry", item.retry, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < contexts.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_dll_invocation_context_array(
    out: &mut String,
    contexts: &[DllInvocationContext],
    indent: usize,
) {
    if contexts.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, item) in contexts.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "source", &item.source, true);
        field_usize(out, indent + 2, "line", item.line, true);
        field_str(out, indent + 2, "item_name", &item.item_name, true);
        field_str(out, indent + 2, "row_label", &item.row_label, true);
        field_str(out, indent + 2, "dll_name", &item.dll_name, true);
        field_str(out, indent + 2, "dll_base_name", &item.dll_base_name, true);
        ind(out, indent + 2);
        out.push_str("\"dll_suffixes\": ");
        write_string_array(out, &item.dll_suffixes, indent + 2);
        out.push_str(",\n");
        field_str(
            out,
            indent + 2,
            "dll_invocation_mode",
            &item.dll_invocation_mode,
            true,
        );
        field_str(out, indent + 2, "dll_function", &item.dll_function, true);
        field_str(out, indent + 2, "evidence", &item.evidence, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < contexts.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_variable_reference_array(
    out: &mut String,
    references: &[VariableReference],
    indent: usize,
) {
    if references.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, reference) in references.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "source", &reference.source, true);
        field_usize(out, indent + 2, "line", reference.line, true);
        field_str(out, indent + 2, "row_label", &reference.row_label, true);
        field_str(out, indent + 2, "token", &reference.token, true);
        field_str(out, indent + 2, "header", &reference.header, true);
        field_opt_str(out, indent + 2, "key", reference.key.as_deref(), true);
        field_str(out, indent + 2, "kind", &reference.kind, true);
        field_str(out, indent + 2, "status", &reference.status, true);
        field_opt_str(
            out,
            indent + 2,
            "resolved_value",
            reference.resolved_value.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "value_source",
            reference.value_source.as_deref(),
            true,
        );
        field_opt_usize(out, indent + 2, "value_line", reference.value_line, true);
        field_str(out, indent + 2, "evidence", &reference.evidence, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < references.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_data_section_array(out: &mut String, sections: &[DataSection], indent: usize) {
    if sections.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, section) in sections.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "source", &section.source, true);
        field_str(out, indent + 2, "name", &section.name, true);
        field_str(out, indent + 2, "display_name", &section.display_name, true);
        field_str(out, indent + 2, "header", &section.header, true);
        field_usize(out, indent + 2, "line", section.line, true);
        ind(out, indent + 2);
        out.push_str("\"entries\": ");
        write_data_entry_array(out, &section.entries, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < sections.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_data_entry_array(out: &mut String, entries: &[DataEntry], indent: usize) {
    if entries.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, entry) in entries.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "key", &entry.key, true);
        field_str(out, indent + 2, "value", &entry.value, true);
        field_usize(out, indent + 2, "line", entry.line, true);
        field_str(out, indent + 2, "raw", &entry.raw, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < entries.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_flow_array(out: &mut String, flows: &[Flow], indent: usize) {
    if flows.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, flow) in flows.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "header", &flow.header, true);
        field_str(out, indent + 2, "kind", flow_kind(&flow.kind), true);
        field_str(out, indent + 2, "station", &flow.station, true);
        field_opt_str(out, indent + 2, "sku", flow.sku.as_deref(), true);
        field_usize(out, indent + 2, "line", flow.line, true);
        ind(out, indent + 2);
        out.push_str("\"items\": ");
        write_string_array(out, &flow.items, indent + 2);
        out.push_str(",\n");
        ind(out, indent + 2);
        out.push_str("\"rows\": ");
        write_flow_rows(out, &flow.rows, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < flows.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_flow_rows(out: &mut String, rows: &[FlowRow], indent: usize) {
    if rows.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, row) in rows.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str(&format!(
            "{{ \"key\": {}, \"item\": {}, \"line\": {} }}",
            q(&row.key),
            q(&row.item),
            row.line
        ));
        if index + 1 < rows.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_diagnostic_array(out: &mut String, diagnostics: &[Diagnostic], indent: usize) {
    if diagnostics.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(
            out,
            indent + 2,
            "severity",
            diagnostic.severity.as_str(),
            true,
        );
        field_str(out, indent + 2, "code", &diagnostic.code, true);
        field_str(out, indent + 2, "file", &diagnostic.file, true);
        field_usize(out, indent + 2, "line", diagnostic.line, true);
        field_str(out, indent + 2, "message", &diagnostic.message, true);
        field_str(out, indent + 2, "evidence", &diagnostic.evidence, true);
        ind(out, indent + 2);
        out.push_str("\"related\": ");
        write_related_array(out, &diagnostic.related, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < diagnostics.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_related_array(out: &mut String, related: &[RelatedLocation], indent: usize) {
    if related.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, item) in related.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str(&format!(
            "{{ \"file\": {}, \"line\": {} }}",
            q(&item.file),
            item.line
        ));
        if index + 1 < related.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_path_checks(out: &mut String, graph: Option<&ScriptFlowGraph>, indent: usize) {
    let Some(graph) = graph else {
        out.push_str("null");
        return;
    };
    out.push_str("{\n");
    field_str(out, indent + 1, "status", &graph.status, true);
    field_str(out, indent + 1, "flow_header", &graph.flow_header, true);
    field_usize(out, indent + 1, "items_checked", graph.item_count, true);
    field_usize(
        out,
        indent + 1,
        "rows_checked",
        graph_row_count(graph),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "pass_paths",
        graph_edge_count(graph, "pass"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "fail_paths",
        graph_edge_count(graph, "fail"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "next_paths",
        graph_next_path_count(graph),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "terminal_paths",
        graph_terminal_path_count(graph),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "macro_calls",
        graph_edge_count(graph, "macro"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "macro_returns",
        graph_edge_count(graph, "macro_return"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "unresolved_paths",
        graph_issue_count(graph, "unresolved_branch_target")
            + graph_issue_count(graph, "unresolved_macro_branch_target"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "missing_next_sections",
        graph_issue_count(graph, "missing_next_section"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "unreachable_rows",
        graph_issue_count(graph, "unreachable_row"),
        true,
    );
    field_usize(
        out,
        indent + 1,
        "potential_infinite_loops",
        graph_issue_count(graph, "potential_infinite_loop"),
        true,
    );
    field_usize(out, indent + 1, "issues", graph.issues.len(), false);
    ind(out, indent);
    out.push('}');
}

fn write_graph_summary(out: &mut String, graph: &ScriptFlowGraph, indent: usize) {
    out.push_str("{\n");
    field_str(out, indent + 1, "status", &graph.status, true);
    field_str(out, indent + 1, "flow_header", &graph.flow_header, true);
    field_usize(out, indent + 1, "item_count", graph.item_count, true);
    field_usize(out, indent + 1, "node_count", graph.node_count, true);
    field_usize(out, indent + 1, "edge_count", graph.edge_count, true);
    field_usize(out, indent + 1, "issue_count", graph.issues.len(), true);
    field_bool(out, indent + 1, "detail_included", false, true);
    field_str(
        out,
        indent + 1,
        "detail",
        "Full segments, nodes, and edges omitted. Re-run with the debug command for graph debug output.",
        false,
    );
    ind(out, indent);
    out.push('}');
}

fn graph_row_count(graph: &ScriptFlowGraph) -> usize {
    graph
        .nodes
        .iter()
        .filter(|node| !node.terminal && !node.label.starts_with("MACRO_RETURN:"))
        .count()
}

fn graph_edge_count(graph: &ScriptFlowGraph, kind: &str) -> usize {
    graph.edges.iter().filter(|edge| edge.kind == kind).count()
}

fn graph_next_path_count(graph: &ScriptFlowGraph) -> usize {
    graph
        .edges
        .iter()
        .filter(|edge| edge.path.eq_ignore_ascii_case("NEXT"))
        .count()
}

fn graph_terminal_path_count(graph: &ScriptFlowGraph) -> usize {
    graph
        .edges
        .iter()
        .filter(|edge| edge.target_kind == "terminal")
        .count()
}

fn graph_issue_count(graph: &ScriptFlowGraph, issue_type: &str) -> usize {
    graph
        .issues
        .iter()
        .filter(|issue| issue.issue_type == issue_type)
        .count()
}

fn write_graph(out: &mut String, graph: &ScriptFlowGraph, indent: usize) {
    out.push_str("{\n");
    field_str(out, indent + 1, "status", &graph.status, true);
    field_str(out, indent + 1, "flow_header", &graph.flow_header, true);
    field_usize(out, indent + 1, "item_count", graph.item_count, true);
    field_usize(out, indent + 1, "node_count", graph.node_count, true);
    field_usize(out, indent + 1, "edge_count", graph.edge_count, true);
    ind(out, indent + 1);
    out.push_str("\"segments\": ");
    write_segment_array(out, &graph.segments, indent + 1);
    out.push_str(",\n");
    ind(out, indent + 1);
    out.push_str("\"nodes\": ");
    write_node_array(out, &graph.nodes, indent + 1);
    out.push_str(",\n");
    ind(out, indent + 1);
    out.push_str("\"edges\": ");
    write_edge_array(out, &graph.edges, indent + 1);
    out.push_str(",\n");
    ind(out, indent + 1);
    out.push_str("\"issues\": ");
    write_issue_array(out, &graph.issues, indent + 1);
    out.push('\n');
    ind(out, indent);
    out.push('}');
}

fn write_segment_array(out: &mut String, segments: &[GraphSegment], indent: usize) {
    if segments.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, segment) in segments.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "item", &segment.item, true);
        field_opt_str(
            out,
            indent + 2,
            "section_header",
            segment.section_header.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "section_item_name",
            segment.section_item_name.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "section_error_code",
            segment.section_error_code.as_deref(),
            true,
        );
        field_opt_u32(
            out,
            indent + 2,
            "section_retry",
            segment.section_retry,
            true,
        );
        field_str(out, indent + 2, "status", &segment.status, true);
        field_usize(out, indent + 2, "row_count", segment.row_count, true);
        ind(out, indent + 2);
        out.push_str("\"nodes\": ");
        write_string_array(out, &segment.nodes, indent + 2);
        out.push_str(",\n");
        ind(out, indent + 2);
        out.push_str("\"edges\": ");
        write_usize_array(out, &segment.edges);
        out.push_str(",\n");
        ind(out, indent + 2);
        out.push_str("\"issues\": ");
        write_issue_array(out, &segment.issues, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < segments.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_node_array(out: &mut String, nodes: &[GraphNode], indent: usize) {
    if nodes.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, node) in nodes.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "id", &node.id, true);
        field_str(out, indent + 2, "item", &node.item, true);
        field_str(out, indent + 2, "label", &node.label, true);
        field_opt_str(
            out,
            indent + 2,
            "label_raw",
            node.label_raw.as_deref(),
            true,
        );
        field_opt_u32(out, indent + 2, "retry", node.retry, true);
        field_opt_usize(out, indent + 2, "line", node.line, true);
        field_opt_str(out, indent + 2, "dll_name", node.dll_name.as_deref(), true);
        field_opt_str(
            out,
            indent + 2,
            "dll_base_name",
            node.dll_base_name.as_deref(),
            true,
        );
        ind(out, indent + 2);
        out.push_str("\"dll_suffixes\": ");
        write_string_array(out, &node.dll_suffixes, indent + 2);
        out.push_str(",\n");
        field_opt_str(
            out,
            indent + 2,
            "dll_invocation_mode",
            node.dll_invocation_mode.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "dll_function",
            node.dll_function.as_deref(),
            true,
        );
        field_opt_str(out, indent + 2, "criteria", node.criteria.as_deref(), true);
        field_opt_str(
            out,
            indent + 2,
            "parameters",
            node.parameters.as_deref(),
            true,
        );
        field_opt_str(out, indent + 2, "timeout", node.timeout.as_deref(), true);
        field_opt_str(
            out,
            indent + 2,
            "pass_path",
            node.pass_path.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "fail_path",
            node.fail_path.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "raw_value",
            node.raw_value.as_deref(),
            true,
        );
        field_bool(out, indent + 2, "terminal", node.terminal, true);
        field_opt_u32(out, indent + 2, "loop_count", node.loop_count, true);
        ind(out, indent + 2);
        out.push_str("\"cycle_ids\": ");
        write_string_array(out, &node.cycle_ids, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < nodes.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_edge_array(out: &mut String, edges: &[GraphEdge], indent: usize) {
    if edges.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, edge) in edges.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "source", &edge.source, true);
        field_str(out, indent + 2, "source_item", &edge.source_item, true);
        field_str(out, indent + 2, "source_label", &edge.source_label, true);
        field_str(out, indent + 2, "kind", &edge.kind, true);
        field_str(out, indent + 2, "path", &edge.path, true);
        field_str(out, indent + 2, "target", &edge.target, true);
        field_str(out, indent + 2, "target_kind", &edge.target_kind, true);
        field_opt_str(
            out,
            indent + 2,
            "target_item",
            edge.target_item.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "target_label",
            edge.target_label.as_deref(),
            true,
        );
        field_opt_str(
            out,
            indent + 2,
            "target_token",
            edge.target_token.as_deref(),
            true,
        );
        ind(out, indent + 2);
        out.push_str("\"cycle_ids\": ");
        write_string_array(out, &edge.cycle_ids, indent + 2);
        out.push('\n');
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < edges.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_issue_array(out: &mut String, issues: &[GraphIssue], indent: usize) {
    if issues.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, issue) in issues.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str("{\n");
        field_str(out, indent + 2, "type", &issue.issue_type, true);
        field_opt_str(out, indent + 2, "item", issue.item.as_deref(), true);
        field_opt_str(out, indent + 2, "label", issue.label.as_deref(), true);
        field_opt_str(out, indent + 2, "target", issue.target.as_deref(), true);
        field_str(out, indent + 2, "message", &issue.message, true);
        field_str(out, indent + 2, "evidence", &issue.evidence, true);
        field_str(out, indent + 2, "detail", &issue.detail, false);
        ind(out, indent + 1);
        out.push('}');
        if index + 1 < issues.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_string_array(out: &mut String, values: &[String], indent: usize) {
    if values.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, value) in values.iter().enumerate() {
        ind(out, indent + 1);
        out.push_str(&q(value));
        if index + 1 < values.len() {
            out.push(',');
        }
        out.push('\n');
    }
    ind(out, indent);
    out.push(']');
}

fn write_usize_array(out: &mut String, values: &[usize]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
}

fn field_str(out: &mut String, indent: usize, name: &str, value: &str, comma: bool) {
    ind(out, indent);
    out.push_str(&format!(
        "\"{name}\": {}{}\n",
        q(value),
        if comma { "," } else { "" }
    ));
}

fn field_opt_str(out: &mut String, indent: usize, name: &str, value: Option<&str>, comma: bool) {
    ind(out, indent);
    match value {
        Some(value) => out.push_str(&format!(
            "\"{name}\": {}{}\n",
            q(value),
            if comma { "," } else { "" }
        )),
        None => out.push_str(&format!(
            "\"{name}\": null{}\n",
            if comma { "," } else { "" }
        )),
    }
}

fn field_usize(out: &mut String, indent: usize, name: &str, value: usize, comma: bool) {
    ind(out, indent);
    out.push_str(&format!(
        "\"{name}\": {value}{}\n",
        if comma { "," } else { "" }
    ));
}

fn field_opt_usize(out: &mut String, indent: usize, name: &str, value: Option<usize>, comma: bool) {
    ind(out, indent);
    match value {
        Some(value) => out.push_str(&format!(
            "\"{name}\": {value}{}\n",
            if comma { "," } else { "" }
        )),
        None => out.push_str(&format!(
            "\"{name}\": null{}\n",
            if comma { "," } else { "" }
        )),
    }
}

fn field_opt_u32(out: &mut String, indent: usize, name: &str, value: Option<u32>, comma: bool) {
    ind(out, indent);
    match value {
        Some(value) => out.push_str(&format!(
            "\"{name}\": {value}{}\n",
            if comma { "," } else { "" }
        )),
        None => out.push_str(&format!(
            "\"{name}\": null{}\n",
            if comma { "," } else { "" }
        )),
    }
}

fn field_bool(out: &mut String, indent: usize, name: &str, value: bool, comma: bool) {
    ind(out, indent);
    out.push_str(&format!(
        "\"{name}\": {value}{}\n",
        if comma { "," } else { "" }
    ));
}

fn flow_kind(kind: &FlowKind) -> &'static str {
    match kind {
        FlowKind::Test => "TEST",
        FlowKind::Init => "INIT",
        FlowKind::Final => "FINAL",
    }
}

fn q(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn csv_cell(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn ind(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}
