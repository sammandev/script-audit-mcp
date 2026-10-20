use std::collections::HashMap;

use crate::diagnostics::{Diagnostic, Severity};
use crate::models::{Flow, FlowKind, FlowRow};
use crate::parser::common::{
    case_key, flow_header, invalid_flow_section_kind, is_ignored_line, parse_any_section,
    parse_flow_row, parse_flow_section,
};

#[derive(Debug, Clone)]
pub struct ParsedMainFlow {
    pub flows: Vec<Flow>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse_main_flow_text(text: &str, source_name: &str) -> ParsedMainFlow {
    let mut flows: Vec<Flow> = Vec::new();
    let mut diagnostics = Vec::new();
    let mut seen_headers: HashMap<String, (usize, usize)> = HashMap::new();
    let mut current_flow_index: Option<usize> = None;

    for (line_index, raw) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if is_ignored_line(raw) {
            continue;
        }

        if let Some(parts) = parse_flow_section(raw) {
            let kind = parts.kind;
            let station = parts.station;
            let sku = parts.sku;
            let header = flow_header(&kind, &station, sku.as_deref());
            let key = format!(
                "{}|{}|{}",
                kind.as_str(),
                case_key(&station),
                sku.as_deref().map(case_key).unwrap_or_default()
            );
            if let Some((first_line, existing_index)) = seen_headers.get(&key).copied() {
                diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        "DUPLICATE_FLOW_HEADER",
                        source_name,
                        line_number,
                        format!("Duplicate {} FLOW header for '{}'.", kind.as_str(), station),
                        raw,
                    )
                    .with_related(source_name, first_line),
                );
                current_flow_index = Some(existing_index);
                continue;
            }

            let flow = Flow {
                header,
                kind: kind.clone(),
                station,
                sku,
                line: line_number,
                items: Vec::new(),
                rows: Vec::new(),
            };
            flows.push(flow);
            let index = flows.len() - 1;
            seen_headers.insert(key, (line_number, index));
            current_flow_index = Some(index);
            continue;
        }

        if let Some(kind_text) = invalid_flow_section_kind(raw) {
            diagnostics.push(Diagnostic::new(
                Severity::Error,
                "FLOW_HEADER_KIND_INVALID",
                source_name,
                line_number,
                format!("Flow section header uses invalid flow term '{kind_text}'; expected INIT FLOW, TEST FLOW, or FINAL FLOW."),
                raw,
            ));
            current_flow_index = None;
            continue;
        }

        if parse_any_section(raw).is_some() {
            current_flow_index = None;
            continue;
        }

        if let Some(index) = current_flow_index {
            if let Some((key, item_raw)) = parse_flow_row(raw) {
                if item_raw != item_raw.trim() {
                    diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        "FLOW_ITEM_WHITESPACE",
                        source_name,
                        line_number,
                        "Flow item contains leading or trailing whitespace inside quotes.",
                        raw,
                    ));
                }
                let item = item_raw.trim().to_string();
                flows[index].items.push(item.clone());
                flows[index].rows.push(FlowRow {
                    key,
                    item,
                    line: line_number,
                });
            } else if raw.contains('=') || raw.trim_start().starts_with('/') {
                diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    "FLOW_ROW_INVALID",
                    source_name,
                    line_number,
                    "Active flow row must use an unquoted key and quoted item value.",
                    raw,
                ));
            }
        }
    }

    validate_flow_name_duplicates(&flows, source_name, &mut diagnostics);

    ParsedMainFlow { flows, diagnostics }
}

fn validate_flow_name_duplicates(
    flows: &[Flow],
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut init_lines: HashMap<String, usize> = HashMap::new();
    let mut final_lines: HashMap<String, usize> = HashMap::new();
    for flow in flows {
        let key = case_key(&flow.station);
        match flow.kind {
            FlowKind::Init => {
                if let Some(first_line) = init_lines.insert(key, flow.line) {
                    diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            "DUPLICATE_INIT_FLOW_NAME",
                            source_name,
                            flow.line,
                            format!(
                                "Duplicate INIT FLOW name '{}'. INIT FLOW names must be unique.",
                                flow.station
                            ),
                            &flow.header,
                        )
                        .with_related(source_name, first_line),
                    );
                }
            }
            FlowKind::Final => {
                if let Some(first_line) = final_lines.insert(key, flow.line) {
                    diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            "DUPLICATE_FINAL_FLOW_NAME",
                            source_name,
                            flow.line,
                            format!("Duplicate FINAL FLOW name '{}'. FINAL FLOW names must be unique, even when TEST FLOW SKUs differ.", flow.station),
                            &flow.header,
                        )
                        .with_related(source_name, first_line),
                    );
                }
            }
            FlowKind::Test => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_test_flow_header_and_items() {
        let parsed = parse_main_flow_text(
            "[TEST FLOW: Demo Station#SKU:X1]\nRUN = \"RUN_SECTION\"\n[RUN_SECTION]\nA = \"DLL|FUNC|NULL|NULL|1|QUIT|FAIL\"\n",
            "MAIN_FLOW.ini",
        );
        let test_flow = parsed
            .flows
            .iter()
            .find(|flow| flow.kind == FlowKind::Test)
            .unwrap();
        assert_eq!(test_flow.header, "[TEST FLOW:Demo Station#SKU:X1]");
        assert_eq!(test_flow.items, vec!["RUN_SECTION"]);
    }

    #[test]
    fn reports_flow_header_term_typo() {
        let parsed = parse_main_flow_text("[TSET FLOW:Demo]\nRUN = \"RUN\"\n", "MAIN_FLOW.ini");
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|item| item.code == "FLOW_HEADER_KIND_INVALID")
        );
    }
}
