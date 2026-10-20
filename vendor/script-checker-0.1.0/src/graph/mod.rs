use std::collections::{HashMap, HashSet};

use crate::analysis::section_lookup;
use crate::models::{Flow, ScriptRow, ScriptSection};
use crate::parser::common::{case_key, is_terminal_token};
use crate::parser::script_sections::ParsedScriptSections;

#[derive(Debug, Clone)]
pub struct ScriptFlowGraph {
    pub status: String,
    pub flow_header: String,
    pub item_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub segments: Vec<GraphSegment>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub issues: Vec<GraphIssue>,
}

#[derive(Debug, Clone)]
pub struct GraphSegment {
    pub item: String,
    pub section_header: Option<String>,
    pub section_item_name: Option<String>,
    pub section_error_code: Option<String>,
    pub section_retry: Option<u32>,
    pub status: String,
    pub row_count: usize,
    pub nodes: Vec<String>,
    pub edges: Vec<usize>,
    pub issues: Vec<GraphIssue>,
}

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub item: String,
    pub label: String,
    pub label_raw: Option<String>,
    pub retry: Option<u32>,
    pub line: Option<usize>,
    pub dll_name: Option<String>,
    pub dll_base_name: Option<String>,
    pub dll_suffixes: Vec<String>,
    pub dll_invocation_mode: Option<String>,
    pub dll_function: Option<String>,
    pub criteria: Option<String>,
    pub parameters: Option<String>,
    pub timeout: Option<String>,
    pub pass_path: Option<String>,
    pub fail_path: Option<String>,
    pub raw_value: Option<String>,
    pub terminal: bool,
    pub loop_count: Option<u32>,
    pub cycle_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub source: String,
    pub source_item: String,
    pub source_label: String,
    pub kind: String,
    pub path: String,
    pub target: String,
    pub target_kind: String,
    pub target_item: Option<String>,
    pub target_label: Option<String>,
    pub target_token: Option<String>,
    pub cycle_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GraphIssue {
    pub issue_type: String,
    pub item: Option<String>,
    pub label: Option<String>,
    pub target: Option<String>,
    pub message: String,
    pub evidence: String,
    pub detail: String,
}

impl GraphIssue {
    fn new(
        issue_type: impl Into<String>,
        item: Option<String>,
        label: Option<String>,
        target: Option<String>,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        let message = message.into();
        Self {
            issue_type: issue_type.into(),
            item,
            label,
            target,
            evidence: evidence.into(),
            detail: message.clone(),
            message,
        }
    }
}

pub fn build_script_flow_graph(
    flow: &Flow,
    script_sections: &ParsedScriptSections,
    macro_sections: Option<&ParsedScriptSections>,
) -> ScriptFlowGraph {
    let sections = section_lookup(&script_sections.sections);
    let macros = macro_sections.map(|parsed| section_lookup(&parsed.sections));
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut segments = Vec::new();
    let mut issues = Vec::new();
    let mut terminal_nodes: HashMap<String, GraphNode> = HashMap::new();
    let mut entry_nodes = Vec::new();

    for (item_index, item) in flow.items.iter().enumerate() {
        let Some(section) = sections.get(&case_key(item)) else {
            let issue = GraphIssue::new(
                "missing_section",
                Some(item.clone()),
                None,
                None,
                format!("Selected TEST FLOW item {item} has no active implementation section."),
                item.clone(),
            );
            issues.push(issue.clone());
            segments.push(GraphSegment {
                item: item.clone(),
                section_header: None,
                section_item_name: None,
                section_error_code: None,
                section_retry: None,
                status: "missing_section".to_string(),
                row_count: 0,
                nodes: Vec::new(),
                edges: Vec::new(),
                issues: vec![issue],
            });
            continue;
        };

        let rows = &section.rows;
        if rows.is_empty() {
            let issue = GraphIssue::new(
                "missing_section",
                Some(item.clone()),
                None,
                None,
                format!("Selected TEST FLOW item {item} has no active implementation rows."),
                section.header.clone(),
            );
            issues.push(issue.clone());
            segments.push(GraphSegment {
                item: item.clone(),
                section_header: Some(section.header.clone()),
                section_item_name: Some(section.name.clone()),
                section_error_code: section.error_code.clone(),
                section_retry: section.retry,
                status: "missing_section".to_string(),
                row_count: 0,
                nodes: Vec::new(),
                edges: Vec::new(),
                issues: vec![issue],
            });
            continue;
        }

        let mut segment_issues = Vec::new();
        let mut segment_nodes = Vec::new();
        let mut segment_edges = Vec::new();
        let label_index: HashMap<String, usize> = rows
            .iter()
            .enumerate()
            .map(|(index, row)| (case_key(&row.label), index))
            .collect();

        entry_nodes.push(node_id(item, &rows[0].label));
        for row in rows {
            let node = row_node(item, row);
            segment_nodes.push(node.id.clone());
            nodes.push(node);
        }

        for (row_index, row) in rows.iter().enumerate() {
            let source_id = node_id(item, &row.label);
            let macro_target = row
                .dll_name
                .trim()
                .eq_ignore_ascii_case("MACRO")
                .then(|| row.dll_function.trim())
                .filter(|target| !target.is_empty());
            let macro_section = macro_target.and_then(|target| {
                macros
                    .as_ref()
                    .and_then(|lookup| lookup.get(&case_key(target)).copied())
                    .map(|section| (target, section))
            });
            if let Some((target_name, macro_section)) = macro_section
                && append_macro_invocation(
                    &source_id,
                    row,
                    item,
                    item_index,
                    row_index,
                    rows,
                    &label_index,
                    flow,
                    &sections,
                    target_name,
                    macro_section,
                    &mut nodes,
                    &mut edges,
                    &mut terminal_nodes,
                    &mut segment_nodes,
                    &mut segment_edges,
                    &mut segment_issues,
                )
            {
                continue;
            }

            for (kind, path) in [("pass", &row.pass_path), ("fail", &row.fail_path)] {
                let mut edge = resolve_path(
                    path,
                    kind,
                    item,
                    item_index,
                    row_index,
                    rows,
                    &label_index,
                    flow,
                    &sections,
                    &mut segment_issues,
                );
                edge.source = source_id.clone();
                edge.source_item = item.clone();
                edge.source_label = row.label.clone();
                if edge.target_kind == "terminal" {
                    terminal_nodes
                        .entry(edge.target.clone())
                        .or_insert_with(|| {
                            terminal_node(item, edge.target_token.as_deref().unwrap_or("terminal"))
                        });
                }
                edges.push(edge);
                segment_edges.push(edges.len() - 1);
            }
        }

        let reachable = reachable_segment_nodes(&segment_edges, &edges, item, &segment_nodes);
        for row in rows {
            let id = node_id(item, &row.label);
            if !reachable.contains(&id) {
                segment_issues.push(GraphIssue::new(
                    "unreachable_row",
                    Some(item.clone()),
                    Some(row.label.clone()),
                    None,
                    format!(
                        "{item} row {} is active but unreachable from the first active row.",
                        row.label
                    ),
                    row.raw.clone(),
                ));
            }
        }
        issues.extend(segment_issues.clone());
        segments.push(GraphSegment {
            item: item.clone(),
            section_header: Some(section.header.clone()),
            section_item_name: Some(section.name.clone()),
            section_error_code: section.error_code.clone(),
            section_retry: section.retry,
            status: if segment_issues.is_empty() {
                "ok".to_string()
            } else {
                "issues".to_string()
            },
            row_count: rows.len(),
            nodes: segment_nodes,
            edges: segment_edges,
            issues: segment_issues,
        });
    }

    nodes.extend(terminal_nodes.into_values());
    detect_loop_cycles(
        &mut nodes,
        &mut edges,
        &mut segments,
        &mut issues,
        &entry_nodes,
    );
    let node_count = nodes.len();
    let edge_count = edges.len();
    ScriptFlowGraph {
        status: if issues.is_empty() {
            "ok".to_string()
        } else {
            "issues".to_string()
        },
        flow_header: flow.header.clone(),
        item_count: flow.items.len(),
        node_count,
        edge_count,
        segments,
        nodes,
        edges,
        issues,
    }
}

fn row_node(item: &str, row: &ScriptRow) -> GraphNode {
    row_node_with_id(node_id(item, &row.label), item, row)
}

fn row_node_with_id(id: String, item: &str, row: &ScriptRow) -> GraphNode {
    GraphNode {
        id,
        item: item.to_string(),
        label: row.label.clone(),
        label_raw: Some(row.label_raw.clone()),
        retry: row.retry,
        line: Some(row.line),
        dll_name: Some(row.dll_name.clone()),
        dll_base_name: Some(row.dll_base_name.clone()),
        dll_suffixes: row.dll_suffixes.clone(),
        dll_invocation_mode: Some(row.dll_invocation_mode.clone()),
        dll_function: Some(row.dll_function.clone()),
        criteria: Some(row.criteria.clone()),
        parameters: Some(row.parameters.clone()),
        timeout: Some(row.timeout.clone()),
        pass_path: Some(row.pass_path.clone()),
        fail_path: Some(row.fail_path.clone()),
        raw_value: Some(row.raw_value.clone()),
        terminal: false,
        loop_count: test_count_value(row),
        cycle_ids: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_macro_invocation(
    caller_id: &str,
    caller_row: &ScriptRow,
    item: &str,
    item_index: usize,
    row_index: usize,
    rows: &[ScriptRow],
    label_index: &HashMap<String, usize>,
    flow: &Flow,
    sections: &HashMap<String, &ScriptSection>,
    target_name: &str,
    macro_section: &ScriptSection,
    nodes: &mut Vec<GraphNode>,
    edges: &mut Vec<GraphEdge>,
    terminal_nodes: &mut HashMap<String, GraphNode>,
    segment_nodes: &mut Vec<String>,
    segment_edges: &mut Vec<usize>,
    segment_issues: &mut Vec<GraphIssue>,
) -> bool {
    let macro_rows = &macro_section.rows;
    if macro_rows.is_empty() {
        segment_issues.push(GraphIssue::new(
            "macro_without_active_rows",
            Some(item.to_string()),
            Some(caller_row.label.clone()),
            Some(target_name.to_string()),
            format!("Macro {target_name} has no active rows to execute."),
            macro_section.header.clone(),
        ));
        return false;
    }

    let invocation_key = format!("{}::{}::{}", item, caller_row.label, row_index);
    let local_label_index: HashMap<String, usize> = macro_rows
        .iter()
        .enumerate()
        .map(|(index, row)| (case_key(&row.label), index))
        .collect();
    let child_ids: Vec<String> = macro_rows
        .iter()
        .enumerate()
        .map(|(index, row)| macro_node_id(item, &invocation_key, target_name, index, &row.label))
        .collect();

    for (index, child) in macro_rows.iter().enumerate() {
        let child_id = child_ids[index].clone();
        nodes.push(row_node_with_id(child_id.clone(), item, child));
        segment_nodes.push(child_id);
        if child.dll_name.trim().eq_ignore_ascii_case("MACRO") {
            segment_issues.push(GraphIssue::new(
                "nested_macro_not_expanded",
                Some(item.to_string()),
                Some(child.label.clone()),
                Some(child.dll_function.clone()),
                format!(
                    "Nested macro {} inside macro {target_name} is represented as a row but is not expanded yet.",
                    child.dll_function
                ),
                child.raw.clone(),
            ));
        }
    }

    edges.push(GraphEdge {
        source: caller_id.to_string(),
        source_item: item.to_string(),
        source_label: caller_row.label.clone(),
        kind: "macro".to_string(),
        path: target_name.to_string(),
        target: child_ids[0].clone(),
        target_kind: "row".to_string(),
        target_item: Some(item.to_string()),
        target_label: Some(macro_rows[0].label.clone()),
        target_token: None,
        cycle_ids: Vec::new(),
    });
    segment_edges.push(edges.len() - 1);

    let mut return_nodes: HashMap<String, String> = HashMap::new();
    for (child_index, child) in macro_rows.iter().enumerate() {
        let child_id = &child_ids[child_index];
        for (kind, path) in [("pass", &child.pass_path), ("fail", &child.fail_path)] {
            let mut edge = resolve_macro_path(
                path,
                kind,
                item,
                target_name,
                child_index,
                macro_rows,
                &local_label_index,
                &child_ids,
                &invocation_key,
                nodes,
                segment_nodes,
                segment_issues,
                &mut return_nodes,
            );
            edge.source = child_id.clone();
            edge.source_item = item.to_string();
            edge.source_label = child.label.clone();
            edges.push(edge);
            segment_edges.push(edges.len() - 1);
        }
    }

    for (outcome, return_id) in return_nodes {
        let path_kind = if outcome == "success" { "pass" } else { "fail" };
        let caller_path = if outcome == "success" {
            &caller_row.pass_path
        } else {
            &caller_row.fail_path
        };
        let mut edge = resolve_path(
            caller_path,
            path_kind,
            item,
            item_index,
            row_index,
            rows,
            label_index,
            flow,
            sections,
            segment_issues,
        );
        edge.source = return_id;
        edge.source_item = item.to_string();
        edge.source_label = format!("MACRO_RETURN:{}", outcome.to_ascii_uppercase());
        edge.kind = "macro_return".to_string();
        if edge.target_kind == "terminal" {
            terminal_nodes
                .entry(edge.target.clone())
                .or_insert_with(|| {
                    terminal_node(item, edge.target_token.as_deref().unwrap_or("terminal"))
                });
        }
        edges.push(edge);
        segment_edges.push(edges.len() - 1);
    }

    true
}

#[allow(clippy::too_many_arguments)]
fn resolve_macro_path(
    token: &str,
    kind: &str,
    item: &str,
    macro_name: &str,
    row_index: usize,
    rows: &[ScriptRow],
    label_index: &HashMap<String, usize>,
    child_ids: &[String],
    invocation_key: &str,
    nodes: &mut Vec<GraphNode>,
    segment_nodes: &mut Vec<String>,
    issues: &mut Vec<GraphIssue>,
    return_nodes: &mut HashMap<String, String>,
) -> GraphEdge {
    let value = token.trim();
    let mut edge = empty_edge(kind, value);
    if value.eq_ignore_ascii_case("NEXT") {
        if row_index + 1 < rows.len() {
            edge.target = child_ids[row_index + 1].clone();
            edge.target_kind = "row".to_string();
            edge.target_item = Some(item.to_string());
            edge.target_label = Some(rows[row_index + 1].label.clone());
            return edge;
        }
        issues.push(GraphIssue::new(
            "macro_next_without_target",
            Some(item.to_string()),
            rows.get(row_index).map(|row| row.label.clone()),
            Some(macro_name.to_string()),
            format!("Macro {macro_name} uses Next at its final active row without an explicit macro return."),
            rows.get(row_index)
                .map(|row| row.raw.clone())
                .unwrap_or_default(),
        ));
        edge.target = value.to_string();
        edge.target_kind = "unresolved".to_string();
        return edge;
    }
    if is_terminal_token(value) {
        let outcome = macro_terminal_outcome(value, kind);
        let return_id = ensure_macro_return_node(
            item,
            macro_name,
            invocation_key,
            &outcome,
            nodes,
            segment_nodes,
            return_nodes,
        );
        edge.target = return_id;
        edge.target_kind = "macro_return".to_string();
        edge.target_item = Some(item.to_string());
        edge.target_label = Some(format!("MACRO_RETURN:{}", outcome.to_ascii_uppercase()));
        edge.target_token = Some(value.to_ascii_uppercase());
        return edge;
    }
    if let Some(target_index) = label_index.get(&case_key(value)).copied() {
        edge.target = child_ids[target_index].clone();
        edge.target_kind = "row".to_string();
        edge.target_item = Some(item.to_string());
        edge.target_label = Some(rows[target_index].label.clone());
        return edge;
    }
    issues.push(GraphIssue::new(
        "unresolved_macro_branch_target",
        Some(item.to_string()),
        rows.get(row_index).map(|row| row.label.clone()),
        Some(value.to_string()),
        format!("Macro {macro_name} {kind} path targets unresolved label {value}."),
        rows.get(row_index)
            .map(|row| row.raw.clone())
            .unwrap_or_default(),
    ));
    edge.target = value.to_string();
    edge.target_kind = "unresolved".to_string();
    edge
}

fn ensure_macro_return_node(
    item: &str,
    macro_name: &str,
    invocation_key: &str,
    outcome: &str,
    nodes: &mut Vec<GraphNode>,
    segment_nodes: &mut Vec<String>,
    return_nodes: &mut HashMap<String, String>,
) -> String {
    if let Some(existing) = return_nodes.get(outcome) {
        return existing.clone();
    }
    let return_id = macro_return_node_id(item, invocation_key, outcome);
    return_nodes.insert(outcome.to_string(), return_id.clone());
    nodes.push(GraphNode {
        id: return_id.clone(),
        item: item.to_string(),
        label: format!("MACRO_RETURN:{}", outcome.to_ascii_uppercase()),
        label_raw: None,
        retry: None,
        line: None,
        dll_name: Some("MACRO".to_string()),
        dll_base_name: Some("MACRO".to_string()),
        dll_suffixes: Vec::new(),
        dll_invocation_mode: Some("normal".to_string()),
        dll_function: Some("RETURN".to_string()),
        criteria: Some(macro_name.to_string()),
        parameters: None,
        timeout: None,
        pass_path: None,
        fail_path: None,
        raw_value: None,
        terminal: false,
        loop_count: None,
        cycle_ids: Vec::new(),
    });
    segment_nodes.push(return_id.clone());
    return_id
}

fn macro_terminal_outcome(token: &str, path_kind: &str) -> String {
    let upper = token.trim().to_ascii_uppercase();
    if upper == "FAIL" {
        "failure".to_string()
    } else if upper == "QUIT" {
        if path_kind == "pass" {
            "success".to_string()
        } else {
            "failure".to_string()
        }
    } else if upper == "PASS" || upper == "END" {
        "success".to_string()
    } else if path_kind == "fail" {
        "failure".to_string()
    } else {
        "success".to_string()
    }
}

fn terminal_node(item: &str, token: &str) -> GraphNode {
    GraphNode {
        id: terminal_node_id(item, token),
        item: item.to_string(),
        label: token.to_ascii_uppercase(),
        label_raw: None,
        retry: None,
        line: None,
        dll_name: None,
        dll_base_name: None,
        dll_suffixes: Vec::new(),
        dll_invocation_mode: None,
        dll_function: None,
        criteria: None,
        parameters: None,
        timeout: None,
        pass_path: None,
        fail_path: None,
        raw_value: None,
        terminal: true,
        loop_count: None,
        cycle_ids: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_path(
    token: &str,
    kind: &str,
    item: &str,
    item_index: usize,
    row_index: usize,
    rows: &[ScriptRow],
    label_index: &HashMap<String, usize>,
    flow: &Flow,
    sections: &HashMap<String, &crate::models::ScriptSection>,
    issues: &mut Vec<GraphIssue>,
) -> GraphEdge {
    let value = token.trim();
    let mut edge = empty_edge(kind, value);
    if value.eq_ignore_ascii_case("NEXT") {
        if row_index + 1 < rows.len() {
            let target = &rows[row_index + 1].label;
            edge.target = node_id(item, target);
            edge.target_kind = "row".to_string();
            edge.target_item = Some(item.to_string());
            edge.target_label = Some(target.clone());
            return edge;
        }
        if item_index + 1 >= flow.items.len() {
            edge.target = terminal_node_id(item, "END");
            edge.target_kind = "terminal".to_string();
            edge.target_token = Some("END".to_string());
            return edge;
        }
        let next_item = &flow.items[item_index + 1];
        if let Some(next_section) = sections
            .get(&case_key(next_item))
            .filter(|section| !section.rows.is_empty())
        {
            let target = &next_section.rows[0].label;
            edge.target = node_id(next_item, target);
            edge.target_kind = "row".to_string();
            edge.target_item = Some(next_item.clone());
            edge.target_label = Some(target.clone());
            return edge;
        }
        issues.push(GraphIssue::new(
            "missing_next_section",
            Some(item.to_string()),
            rows.get(row_index).map(|row| row.label.clone()),
            Some(next_item.clone()),
            format!("Next handoff from {item} targets {next_item}, but that implementation section has no active rows."),
            rows.get(row_index)
                .map(|row| row.raw.clone())
                .unwrap_or_default(),
        ));
        edge.target = format!("{next_item}::section");
        edge.target_kind = "missing_section".to_string();
        edge.target_item = Some(next_item.clone());
        return edge;
    }
    if is_terminal_token(value) {
        edge.target = terminal_node_id(item, value);
        edge.target_kind = "terminal".to_string();
        edge.target_token = Some(value.to_ascii_uppercase());
        return edge;
    }
    if let Some(target_index) = label_index
        .get(&case_key(&crate::parser::common::label_without_retry(
            value,
        )))
        .copied()
    {
        let target = &rows[target_index].label;
        edge.target = node_id(item, target);
        edge.target_kind = "row".to_string();
        edge.target_item = Some(item.to_string());
        edge.target_label = Some(target.clone());
        return edge;
    }
    issues.push(GraphIssue::new(
        "unresolved_branch_target",
        Some(item.to_string()),
        rows.get(row_index).map(|row| row.label.clone()),
        Some(value.to_string()),
        format!("{item} {kind} path targets unresolved label {value}."),
        rows.get(row_index)
            .map(|row| row.raw.clone())
            .unwrap_or_default(),
    ));
    edge.target = value.to_string();
    edge.target_kind = "unresolved".to_string();
    edge
}

fn empty_edge(kind: &str, path: &str) -> GraphEdge {
    GraphEdge {
        source: String::new(),
        source_item: String::new(),
        source_label: String::new(),
        kind: kind.to_string(),
        path: if path.is_empty() {
            "-".to_string()
        } else {
            path.to_string()
        },
        target: String::new(),
        target_kind: String::new(),
        target_item: None,
        target_label: None,
        target_token: None,
        cycle_ids: Vec::new(),
    }
}

fn reachable_segment_nodes(
    segment_edges: &[usize],
    edges: &[GraphEdge],
    item: &str,
    segment_nodes: &[String],
) -> HashSet<String> {
    let segment_node_set: HashSet<String> = segment_nodes.iter().cloned().collect();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    for edge_index in segment_edges {
        let edge = &edges[*edge_index];
        if segment_node_set.contains(&edge.target) && edge.target_item.as_deref() == Some(item) {
            adjacency
                .entry(edge.source.clone())
                .or_default()
                .push(edge.target.clone());
        }
    }
    let mut reachable = HashSet::new();
    if let Some(first) = segment_nodes.first() {
        let mut stack = vec![first.clone()];
        while let Some(current) = stack.pop() {
            if !reachable.insert(current.clone()) {
                continue;
            }
            if let Some(targets) = adjacency.get(&current) {
                stack.extend(targets.iter().cloned());
            }
        }
    }
    reachable
}

fn detect_loop_cycles(
    nodes: &mut [GraphNode],
    edges: &mut [GraphEdge],
    segments: &mut [GraphSegment],
    issues: &mut Vec<GraphIssue>,
    entry_nodes: &[String],
) {
    let graph_node_ids: HashSet<String> = nodes
        .iter()
        .filter(|node| !node.terminal)
        .map(|node| node.id.clone())
        .collect();
    let mut adjacency: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for (index, edge) in edges.iter().enumerate() {
        if graph_node_ids.contains(&edge.source) && graph_node_ids.contains(&edge.target) {
            adjacency
                .entry(edge.source.clone())
                .or_default()
                .push((edge.target.clone(), index));
        }
    }

    let mut reachable = HashSet::new();
    let mut stack: Vec<String> = entry_nodes.to_vec();
    while let Some(current) = stack.pop() {
        if !reachable.insert(current.clone()) {
            continue;
        }
        if let Some(targets) = adjacency.get(&current) {
            stack.extend(targets.iter().map(|(target, _)| target.clone()));
        }
    }

    let node_by_id: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.clone(), index))
        .collect();
    let components = strongly_connected_components(&adjacency, &graph_node_ids);
    let mut cycle_number = 0;
    for component_values in components {
        let component: HashSet<String> = component_values.into_iter().collect();
        let has_self_loop = component.len() == 1
            && adjacency
                .get(component.iter().next().unwrap())
                .is_some_and(|targets| {
                    targets.iter().any(|(target, _)| component.contains(target))
                });
        if component.len() == 1 && !has_self_loop {
            continue;
        }
        if component.is_disjoint(&reachable) {
            continue;
        }
        let loop_node_ids: Vec<String> = component
            .iter()
            .filter(|node_id| {
                node_by_id.get(*node_id).is_some_and(|index| {
                    nodes[*index]
                        .dll_function
                        .as_deref()
                        .unwrap_or_default()
                        .eq_ignore_ascii_case("LOOP")
                })
            })
            .cloned()
            .collect();
        if loop_node_ids.is_empty() {
            continue;
        }
        let mut fail_reentry_edges = Vec::new();
        for node_id in &loop_node_ids {
            for (target, edge_index) in adjacency.get(node_id).into_iter().flatten() {
                if component.contains(target) && edges[*edge_index].kind == "fail" {
                    fail_reentry_edges.push(*edge_index);
                }
            }
        }
        if fail_reentry_edges.is_empty() {
            continue;
        }
        cycle_number += 1;
        let cycle_id = format!("cycle-{cycle_number}");
        for node_id in &component {
            if let Some(index) = node_by_id.get(node_id).copied() {
                nodes[index].cycle_ids.push(cycle_id.clone());
            }
        }
        for edge_index in fail_reentry_edges {
            edges[edge_index].cycle_ids.push(cycle_id.clone());
        }
        let mut labels: Vec<String> = component
            .iter()
            .filter_map(|node_id| {
                node_by_id
                    .get(node_id)
                    .map(|index| nodes[*index].label.clone())
            })
            .collect();
        labels.sort();
        let item = component.iter().find_map(|node_id| {
            node_by_id
                .get(node_id)
                .map(|index| nodes[*index].item.clone())
        });
        let issue = GraphIssue::new(
            "potential_infinite_loop",
            item.clone(),
            None,
            Some(cycle_id),
            format!(
                "Potential infinite loop detected: {}. A Loop controller's FailPath re-enters the reachable cycle after its configured loop budget can be exhausted.",
                labels.join(" -> ")
            ),
            labels.join(" -> "),
        );
        issues.push(issue.clone());
        if let Some(item) = item {
            for segment in segments.iter_mut().filter(|segment| segment.item == item) {
                segment.status = "issues".to_string();
                segment.issues.push(issue.clone());
            }
        }
    }
}

fn strongly_connected_components(
    adjacency: &HashMap<String, Vec<(String, usize)>>,
    node_ids: &HashSet<String>,
) -> Vec<Vec<String>> {
    struct Tarjan<'a> {
        adjacency: &'a HashMap<String, Vec<(String, usize)>>,
        node_ids: &'a HashSet<String>,
        index: usize,
        indexes: HashMap<String, usize>,
        lowlinks: HashMap<String, usize>,
        stack: Vec<String>,
        on_stack: HashSet<String>,
        components: Vec<Vec<String>>,
    }

    impl Tarjan<'_> {
        fn visit(&mut self, node_id: String) {
            self.indexes.insert(node_id.clone(), self.index);
            self.lowlinks.insert(node_id.clone(), self.index);
            self.index += 1;
            self.stack.push(node_id.clone());
            self.on_stack.insert(node_id.clone());

            for (target, _) in self.adjacency.get(&node_id).into_iter().flatten() {
                if !self.node_ids.contains(target) {
                    continue;
                }
                if !self.indexes.contains_key(target) {
                    self.visit(target.clone());
                    let lowlink = self.lowlinks[&node_id].min(self.lowlinks[target]);
                    self.lowlinks.insert(node_id.clone(), lowlink);
                } else if self.on_stack.contains(target) {
                    let lowlink = self.lowlinks[&node_id].min(self.indexes[target]);
                    self.lowlinks.insert(node_id.clone(), lowlink);
                }
            }

            if self.lowlinks[&node_id] == self.indexes[&node_id] {
                let mut component = Vec::new();
                while let Some(member) = self.stack.pop() {
                    self.on_stack.remove(&member);
                    component.push(member.clone());
                    if member == node_id {
                        break;
                    }
                }
                self.components.push(component);
            }
        }
    }

    let mut tarjan = Tarjan {
        adjacency,
        node_ids,
        index: 0,
        indexes: HashMap::new(),
        lowlinks: HashMap::new(),
        stack: Vec::new(),
        on_stack: HashSet::new(),
        components: Vec::new(),
    };
    let mut sorted_nodes: Vec<String> = node_ids.iter().cloned().collect();
    sorted_nodes.sort();
    for node_id in sorted_nodes {
        if !tarjan.indexes.contains_key(&node_id) {
            tarjan.visit(node_id);
        }
    }
    tarjan.components
}

fn test_count_value(row: &ScriptRow) -> Option<u32> {
    let text = format!("{}|{}|{}", row.criteria, row.parameters, row.raw_value);
    let marker = "TEST_COUNT";
    let upper = text.to_ascii_uppercase();
    let start = upper.find(marker)?;
    let suffix = &text[start + marker.len()..];
    let digits: String = suffix
        .chars()
        .skip_while(|ch| *ch == ' ' || *ch == ',')
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse::<u32>().ok()
}

fn node_id(item: &str, label: &str) -> String {
    format!("{item}::{label}")
}

fn macro_node_id(
    item: &str,
    invocation_key: &str,
    macro_name: &str,
    row_index: usize,
    label: &str,
) -> String {
    format!("{item}::macro::{invocation_key}::{macro_name}::{row_index}::{label}")
}

fn macro_return_node_id(item: &str, invocation_key: &str, outcome: &str) -> String {
    format!("{item}::macro_return::{invocation_key}::{outcome}")
}

fn terminal_node_id(item: &str, token: &str) -> String {
    format!("{item}::terminal::{}", token.trim().to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use crate::parser::main_flow::parse_main_flow_text;
    use crate::parser::script_sections::parse_script_sections_text;

    use super::*;

    #[test]
    fn next_at_item_boundary_uses_next_section_first_row() {
        let text = "[TEST FLOW:Demo]\nA = \"A\"\nB = \"B\"\n[A]\nRUN = \"DLL|FUNC|NULL|NULL|1|Next|FAIL\"\n[B]\nSTART = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n";
        let flow = parse_main_flow_text(text, "MAIN_FLOW.ini").flows.remove(0);
        let sections = parse_script_sections_text(text, "MAIN_FLOW.ini");
        let graph = build_script_flow_graph(&flow, &sections, None);
        assert!(graph.edges.iter().any(|edge| edge.source == "A::RUN"
            && edge.kind == "pass"
            && edge.target == "B::START"));
    }

    #[test]
    fn expands_macro_rows_and_returns_to_caller_paths() {
        let main = "[TEST FLOW:Demo]\nRUN = \"RUN\"\n[RUN]\nCALL = \"MACRO|DEMO_MACRO|NULL|NULL|1|AFTER_PASS|AFTER_FAIL\"\nAFTER_PASS = \"DLL|PASS|NULL|NULL|1|QUIT|FAIL\"\nAFTER_FAIL = \"DLL|FAIL|NULL|NULL|1|QUIT|FAIL\"\n";
        let macros = "[DEMO_MACRO]\nSTEP_ONE = \"DLL|STEP|NULL|NULL|1|STEP_TWO|FAIL\"\nSTEP_TWO = \"DLL|DONE|NULL|NULL|1|QUIT|FAIL\"\n";
        let flow = parse_main_flow_text(main, "MAIN_FLOW.ini").flows.remove(0);
        let main_sections = parse_script_sections_text(main, "MAIN_FLOW.ini");
        let macro_sections = parse_script_sections_text(macros, "MACRO_LIST.ini");

        let graph = build_script_flow_graph(&flow, &main_sections, Some(&macro_sections));

        assert!(graph.nodes.iter().any(|node| node.label == "STEP_ONE"));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.kind == "macro" && edge.source == "RUN::CALL")
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "macro_return"
                && edge.source_label == "MACRO_RETURN:SUCCESS"
                && edge.target == "RUN::AFTER_PASS"
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "macro_return"
                && edge.source_label == "MACRO_RETURN:FAILURE"
                && edge.target == "RUN::AFTER_FAIL"
        }));
    }
}
