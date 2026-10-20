use std::collections::{HashMap, HashSet, VecDeque};

use script_checker::{
    analysis::AnalysisOutput,
    models::{DataSection, ScriptRow, ScriptSection},
    parser::common::{canonical_header, label_without_retry},
};
use serde::Serialize;

use super::{BundleDiagnostic, MAX_EXPANDED_ROWS, ValidateBundleRequest};

pub const MAX_REFERENCE_STEPS: usize = 65_536;
pub const MAX_RESOLVED_BYTES: usize = 32_768;
pub const MAX_TOTAL_RESOLVED_BYTES: usize = 4_194_304;
pub const MAX_EXECUTION_EDGES: usize = 65_536;
pub const MAX_CYCLE_STEPS: usize = 65_536;

#[derive(Debug, Serialize)]
pub struct ExecutionRow {
    pub id: String,
    pub file: String,
    pub section: String,
    pub line: usize,
    pub row: String,
    pub call_site: Option<String>,
    pub device: String,
    pub function: String,
    pub parameters: String,
    pub criteria: String,
    pub timeout: String,
    pub pass_path: String,
    pub fail_path: String,
    pub row_retry: Option<u32>,
    pub item_retry: Option<u32>,
    pub loop_budget: Option<u32>,
    pub references: &'static str,
    pub reachability: &'static str,
    pub redacted: bool,
}

#[derive(Debug, Serialize)]
pub struct ExecutionEdge {
    pub source: String,
    pub target: String,
    pub kind: &'static str,
    pub certainty: &'static str,
}

#[derive(Clone, Copy)]
enum Target {
    Row(usize),
    Terminal(&'static str),
    Unknown,
}

struct Run<'a> {
    section: &'a ScriptSection,
    nodes: Vec<usize>,
    next: Target,
    returns: Option<[Target; 2]>,
}

struct Bindings {
    params: Arguments,
    criteria: Arguments,
}

enum Arguments {
    Named(HashMap<String, String>),
    Ambiguous,
    Unsupported,
}

pub(super) fn has_reference(value: &str) -> bool {
    reference_start(value).is_some()
}

fn reference_start(value: &str) -> Option<usize> {
    value
        .match_indices('*')
        .map(|(index, _)| index)
        .find(|index| value.as_bytes().get(*index + 2) == Some(&b':'))
}

pub(super) fn analyze(
    analysis: &AnalysisOutput,
    request: &ValidateBundleRequest,
    diagnostics: &mut Vec<BundleDiagnostic>,
    secrets: &mut Vec<String>,
) -> (Vec<ExecutionRow>, Vec<ExecutionEdge>) {
    let mut data = HashMap::<String, Vec<&DataSection>>::new();
    for section in &analysis.data_sections {
        data.entry(section.name.to_ascii_lowercase())
            .or_default()
            .push(section);
    }
    let mut runtime_keys = HashMap::<String, HashSet<String>>::new();
    for row in analysis
        .script_sections
        .iter()
        .flat_map(|section| &section.rows)
    {
        if row.dll_function.eq_ignore_ascii_case("RECORD_TESTRESULT")
            && row.criteria.split(['&', ';', ',']).any(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("RECORD_TIMES"))
            })
            && let Some(name) = row.dll_base_name.trim().strip_prefix("DLL")
        {
            let name = name.trim_start_matches('_');
            if !name.is_empty() {
                runtime_keys
                    .entry(format!("dll_{name}").to_ascii_lowercase())
                    .or_default()
                    .insert("record_times".into());
            }
        }
    }
    let mut analyzer = Analyzer {
        analysis,
        resolver: Resolver {
            data,
            diagnostics,
            steps: 0,
            bytes: 0,
            bindings: None,
            runtime_keys,
            runtime_writes_unknown: false,
            sensitive_tokens: secrets
                .iter()
                .flat_map(|secret| {
                    secret.match_indices('*').filter_map(|(start, _)| {
                        let tail = &secret[start..];
                        if reference_start(tail) != Some(0) {
                            return None;
                        }
                        tail.find('#').map(|end| tail[..=end].to_string())
                    })
                })
                .collect(),
            resolved_secrets: HashSet::new(),
            dynamic: analysis
                .variable_references
                .iter()
                .filter(|reference| reference.status == "dynamic")
                .map(|reference| reference.token.to_ascii_lowercase())
                .collect(),
            runtime_sections: analysis
                .script_sections
                .iter()
                .flat_map(|section| &section.rows)
                .filter(|row| row.dll_function.eq_ignore_ascii_case("SFIS_TO_VAR"))
                .flat_map(|row| row.criteria.split(['&', ',', ';']))
                .filter(|name| {
                    !name.is_empty()
                        && !name.eq_ignore_ascii_case("NULL")
                        && !name.contains(['=', '*'])
                })
                .map(|name| name.trim().to_ascii_lowercase())
                .collect(),
        },
        execution: Vec::new(),
        edges: Vec::new(),
        links: Vec::new(),
        loop_failures: Vec::new(),
        deferred_calls: Vec::new(),
        legacy: request.dialect == super::BundleDialect::CheckerLegacy,
        edge_limited: false,
        row_limited: false,
        dispatch_unknown: false,
    };
    analyzer.resolver.index_runtime_writes(analysis);
    let flow = analysis
        .flows
        .iter()
        .find(|flow| canonical_header(&flow.header) == canonical_header(&request.selected_flow));
    let mut runs = Vec::new();
    if let Some(flow) = flow {
        for item in &flow.items {
            let matching: Vec<_> = analysis
                .script_sections
                .iter()
                .filter(|section| {
                    section.source.eq_ignore_ascii_case("MAIN_FLOW.ini")
                        && section.name.eq_ignore_ascii_case(item)
                })
                .collect();
            if matching.len() == 1 {
                runs.push(Some(analyzer.allocate(matching[0], None, None)));
            } else {
                runs.push(None);
            }
        }
    }
    let entry = runs
        .first()
        .and_then(Option::as_ref)
        .and_then(|run| run.nodes.first())
        .copied();
    for index in 0..runs.len() {
        let next = if index + 1 == runs.len() {
            Target::Terminal("END")
        } else {
            runs[index + 1]
                .as_ref()
                .and_then(|run| run.nodes.first())
                .copied()
                .map_or(Target::Unknown, Target::Row)
        };
        if let Some(run) = &mut runs[index] {
            run.next = next;
        }
    }
    for run in runs.iter().flatten() {
        analyzer.connect(run);
    }
    for section in &analysis.script_sections {
        let deferred = analyzer
            .deferred_calls
            .iter()
            .any(|(_, name)| name.eq_ignore_ascii_case(&section.name))
            && section.source.eq_ignore_ascii_case("MACRO_LIST.ini")
            && !analyzer.execution.iter().any(|row| {
                row.file == section.source && row.section == section.name && row.call_site.is_none()
            });
        if !deferred
            && section.rows.iter().all(|row| {
                analyzer
                    .execution
                    .iter()
                    .any(|evidence| evidence.file == section.source && evidence.line == row.line)
            })
        {
            continue;
        }
        let run = analyzer.allocate(section, None, None);
        analyzer.connect(&run);
    }
    for (source, name) in std::mem::take(&mut analyzer.deferred_calls) {
        if analyzer.edge_limited {
            break;
        }
        let targets: Vec<_> = analyzer
            .execution
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.file.eq_ignore_ascii_case("MACRO_LIST.ini")
                    && row.section.eq_ignore_ascii_case(&name)
            })
            .map(|(index, _)| index)
            .collect();
        for target in targets {
            analyzer.edge(source, Target::Row(target), "unsupported_macro_body", true);
        }
    }
    analyzer.loop_exhaustion();
    for section in &analysis.data_sections {
        for entry in &section.entries {
            if has_reference(&entry.value) {
                analyzer.resolver.resolve_at(
                    &entry.value,
                    ReferenceSite {
                        file: &section.source,
                        section: &section.name,
                        line: entry.line,
                        row: &entry.key,
                    },
                    "value",
                );
            }
        }
    }
    analyzer.reachability(entry);
    if analyzer.dispatch_unknown {
        for row in &mut analyzer.execution {
            if row.reachability == "unreachable" {
                row.reachability = "unknown";
            }
        }
    }
    if analyzer.edge_limited
        || analyzer.row_limited
        || entry.is_none()
        || analyzer
            .resolver
            .diagnostics
            .iter()
            .any(|issue| issue.layer == "structure" && issue.severity == "error")
    {
        for row in &mut analyzer.execution {
            row.reachability = "unknown";
        }
    }
    secrets.extend(
        analyzer
            .resolver
            .resolved_secrets
            .into_iter()
            .filter(|value| !value.is_empty()),
    );
    (analyzer.execution, analyzer.edges)
}

struct Analyzer<'a, 'b> {
    analysis: &'a AnalysisOutput,
    resolver: Resolver<'a, 'b>,
    execution: Vec<ExecutionRow>,
    edges: Vec<ExecutionEdge>,
    links: Vec<(usize, usize, bool)>,
    loop_failures: Vec<(usize, usize)>,
    deferred_calls: Vec<(usize, String)>,
    legacy: bool,
    edge_limited: bool,
    row_limited: bool,
    dispatch_unknown: bool,
}

impl<'a> Analyzer<'a, '_> {
    fn allocate(
        &mut self,
        section: &'a ScriptSection,
        call_site: Option<usize>,
        bindings: Option<Bindings>,
    ) -> Run<'a> {
        self.resolver.bindings = bindings;
        let mut nodes = Vec::new();
        for (row_index, row) in section.rows.iter().enumerate() {
            if self.execution.len() >= MAX_EXPANDED_ROWS {
                self.row_limited = true;
                self.control_issue(
                    section,
                    row,
                    "EXPANSION_LIMIT",
                    "Execution expansion reached 16384 rows; omitted paths remain unknown.",
                );
                break;
            }
            let mut complete = true;
            let mut resolve = |value: &str, field| {
                let (value, resolved) = self.resolver.resolve(value, section, row, field);
                complete &= resolved;
                value
            };
            let device = resolve(&row.dll_name, "device");
            let function = resolve(&row.dll_function, "function");
            let parameters = resolve(&row.criteria, "parameters");
            let criteria = resolve(&row.parameters, "criteria");
            let timeout = resolve(&row.timeout, "timeout");
            let pass_path = resolve(&row.pass_path, "pass_path");
            let fail_path = resolve(&row.fail_path, "fail_path");
            let loop_budget = if function.eq_ignore_ascii_case("LOOP") {
                parameters
                    .strip_prefix("TEST_COUNT,")
                    .and_then(|count| count.trim().parse::<u32>().ok())
            } else {
                None
            };
            if function.eq_ignore_ascii_case("LOOP") && loop_budget.is_none() {
                self.control_issue(section, row, "LOOP_BUDGET_UNSUPPORTED", "Only a literal TEST_COUNT,<u32> loop budget is inspected; runtime loop behavior is unchecked.");
            }
            for (field, raw, budget) in [
                ("row_retry", row.label_raw.as_str(), row.retry),
                ("item_retry", section.header.as_str(), section.retry),
            ] {
                if (field == "row_retry" || row_index == 0)
                    && budget.is_none()
                    && raw
                        .split_once('#')
                        .is_some_and(|(_, suffix)| suffix.to_ascii_lowercase().contains("retry:"))
                {
                    self.resolver.diagnostics.push(
                        BundleDiagnostic::new("control_flow", "RETRY_BUDGET_UNSUPPORTED", "Retry annotation is not a supported u32 budget; retry behavior remains unknown.")
                            .at(&section.source, row.line, Some(&section.name), Some(&row.label_raw))
                            .field(field, None)
                            .unchecked(),
                    );
                }
            }
            let index = self.execution.len();
            nodes.push(index);
            self.execution.push(ExecutionRow {
                id: format!("row:{index}"),
                file: section.source.clone(),
                section: section.name.clone(),
                line: row.line,
                row: row.label_raw.clone(),
                call_site: call_site.map(|index| format!("row:{index}")),
                device,
                function,
                parameters,
                criteria,
                timeout,
                pass_path,
                fail_path,
                row_retry: row.retry,
                item_retry: section.retry,
                loop_budget,
                references: if complete { "resolved" } else { "unknown" },
                reachability: "unreachable",
                redacted: false,
            });
            if has_reference(&row.timeout)
                && !has_reference(&self.execution[index].timeout)
                && !self.execution[index].timeout.eq_ignore_ascii_case("NULL")
                && (self.execution[index].timeout.is_empty()
                    || !self.execution[index]
                        .timeout
                        .bytes()
                        .all(|byte| byte.is_ascii_digit()))
            {
                self.resolver.diagnostics.push(
                    BundleDiagnostic::new(
                        "structure",
                        "WAIT_TIME_NOT_INTEGER",
                        "Resolved timeout must contain decimal digits or NULL.",
                    )
                    .at(
                        &section.source,
                        row.line,
                        Some(&section.name),
                        Some(&row.label_raw),
                    )
                    .field("timeout", None),
                );
            }
        }
        self.resolver.bindings = None;
        Run {
            section,
            nodes,
            next: Target::Terminal("END"),
            returns: None,
        }
    }

    fn control_issue(
        &mut self,
        section: &ScriptSection,
        row: &ScriptRow,
        code: &str,
        message: &str,
    ) {
        self.resolver.diagnostics.push(
            BundleDiagnostic::new("control_flow", code, message)
                .at(
                    &section.source,
                    row.line,
                    Some(&section.name),
                    Some(&row.label_raw),
                )
                .unchecked(),
        );
    }

    fn target(&mut self, run: &Run<'a>, index: usize, token: &str, pass: bool) -> Target {
        if token == "NEXT" {
            if let Some(next) = run.nodes.get(index + 1) {
                return Target::Row(*next);
            }
            if run.returns.is_some() {
                self.control_issue(
                    run.section,
                    &run.section.rows[index],
                    "MACRO_FALLTHROUGH_UNSUPPORTED",
                    "Final NEXT in a macro has no audited return outcome.",
                );
                return Target::Unknown;
            }
            return run.next;
        }
        if let Some(terminal) = ["PASS", "FAIL", "QUIT", "END"]
            .into_iter()
            .find(|terminal| *terminal == token)
        {
            let success = terminal == "PASS" || terminal == "END" || (terminal == "QUIT" && pass);
            return run.returns.map_or(Target::Terminal(terminal), |returns| {
                returns[usize::from(!success)]
            });
        }
        if ["NEXT", "PASS", "FAIL", "QUIT", "END"]
            .iter()
            .any(|control| token.eq_ignore_ascii_case(control))
        {
            let raw = if pass {
                &run.section.rows[index].pass_path
            } else {
                &run.section.rows[index].fail_path
            };
            if has_reference(raw) {
                let mut issue = BundleDiagnostic::new("control_flow", "DIALECT_TOKEN_CASE", "HH5K control tokens require uppercase; legacy interpretation is not runtime proof.")
                    .at(&run.section.source, run.section.rows[index].line, Some(&run.section.name), Some(&run.section.rows[index].label_raw))
                    .field(if pass { "pass_path" } else { "fail_path" }, Some(token));
                if self.legacy {
                    issue = issue.unchecked();
                }
                self.resolver.diagnostics.push(issue);
            }
            return Target::Unknown;
        }
        let label = label_without_retry(token);
        let matches: Vec<_> = run
            .section
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.label.eq_ignore_ascii_case(&label))
            .collect();
        if matches.len() == 1 {
            return run
                .nodes
                .get(matches[0].0)
                .copied()
                .map_or(Target::Unknown, Target::Row);
        }
        if matches.len() > 1 {
            self.control_issue(
                run.section,
                &run.section.rows[index],
                "BRANCH_LABEL_AMBIGUOUS",
                "Repeated branch labels are preserved, but selecting one is not audited.",
            );
            for (target, _) in matches {
                if let Some(target) = run.nodes.get(target) {
                    self.edge(
                        run.nodes[index],
                        Target::Row(*target),
                        "ambiguous_branch",
                        true,
                    );
                }
            }
        }
        if has_reference(token) {
            self.control_issue(
                run.section,
                &run.section.rows[index],
                "DYNAMIC_CONTROL_UNSUPPORTED",
                "Runtime-dependent routing cannot establish a static execution path.",
            );
        } else if has_reference(if pass {
            &run.section.rows[index].pass_path
        } else {
            &run.section.rows[index].fail_path
        }) {
            self.resolver.diagnostics.push(BundleDiagnostic::new("control_flow", "BRANCH_TARGET_MISSING", "Resolved branch target is not a section-local label or an audited control token.")
                .at(&run.section.source, run.section.rows[index].line, Some(&run.section.name), Some(&run.section.rows[index].label_raw))
                .field(if pass { "pass_path" } else { "fail_path" }, Some(token)));
        }
        Target::Unknown
    }

    fn edge(&mut self, source: usize, target: Target, kind: &'static str, unknown: bool) {
        if self.edges.len() >= MAX_EXECUTION_EDGES {
            if !self.edge_limited {
                let row = &self.execution[source];
                self.resolver.diagnostics.push(
                    BundleDiagnostic::new(
                        "control_flow",
                        "EXECUTION_EDGE_LIMIT",
                        "Execution graph reached 65536 edges; reachability remains unknown.",
                    )
                    .at(&row.file, row.line, Some(&row.section), Some(&row.row))
                    .unchecked(),
                );
            }
            self.edge_limited = true;
            return;
        }
        if let Target::Row(target) = target {
            self.links.push((source, target, unknown));
            if !unknown
                && kind == "fail"
                && self.execution[source].function.eq_ignore_ascii_case("LOOP")
            {
                self.loop_failures.push((source, target));
            }
        }
        self.edges.push(ExecutionEdge {
            source: format!("row:{source}"),
            target: match target {
                Target::Row(index) => format!("row:{index}"),
                Target::Terminal(token) => format!("terminal:{token}"),
                Target::Unknown => "unknown".into(),
            },
            kind,
            certainty: if unknown || matches!(target, Target::Unknown) {
                "unknown"
            } else {
                "supported"
            },
        });
    }

    fn connect(&mut self, run: &Run<'a>) {
        for (index, source) in run.nodes.iter().copied().enumerate() {
            if self.edge_limited {
                break;
            }
            let pass_path = self.execution[source].pass_path.clone();
            let fail_path = self.execution[source].fail_path.clone();
            let pass = self.target(run, index, &pass_path, true);
            let fail = self.target(run, index, &fail_path, false);
            let device = &self.execution[source].device;
            let unknown_dispatch = has_reference(device)
                || has_reference(&self.execution[source].function)
                || device
                    .split('#')
                    .skip(1)
                    .any(|suffix| !["QUICK", "PROXY"].contains(&suffix))
                || device.to_ascii_uppercase().starts_with("MACRO#");
            if unknown_dispatch {
                self.dispatch_unknown = true;
                self.control_issue(
                    run.section,
                    &run.section.rows[index],
                    "DISPATCH_CONTROL_UNCHECKED",
                    "Unresolved or unaudited dispatch cannot prove its execution continuations.",
                );
            }
            if matches!(pass, Target::Unknown) || matches!(fail, Target::Unknown) {
                for target in run
                    .nodes
                    .iter()
                    .copied()
                    .map(Target::Row)
                    .chain(std::iter::once(run.next))
                    .chain(run.returns.into_iter().flatten())
                {
                    self.edge(source, target, "unsupported_continuation", true);
                }
            }
            if self.execution[source].device.eq_ignore_ascii_case("MACRO") {
                let name = self.execution[source].function.clone();
                let targets: Vec<_> = self
                    .analysis
                    .script_sections
                    .iter()
                    .filter(|section| {
                        section.source.eq_ignore_ascii_case("MACRO_LIST.ini")
                            && section.name.eq_ignore_ascii_case(&name)
                            && !section.rows.is_empty()
                    })
                    .collect();
                if run.section.source.eq_ignore_ascii_case("MAIN_FLOW.ini") && targets.len() == 1 {
                    let bindings = Bindings {
                        params: named_arguments(&self.execution[source].parameters),
                        criteria: named_arguments(&self.execution[source].criteria),
                    };
                    let mut child = self.allocate(targets[0], Some(source), Some(bindings));
                    child.returns = Some([pass, fail]);
                    self.edge(
                        source,
                        child
                            .nodes
                            .first()
                            .copied()
                            .map_or(Target::Unknown, Target::Row),
                        "macro_call",
                        false,
                    );
                    self.connect(&child);
                    continue;
                }
                self.control_issue(run.section, &run.section.rows[index], if run.section.name.eq_ignore_ascii_case(&name) { "MACRO_RECURSION_UNSUPPORTED" } else { "MACRO_EXPANSION_UNSUPPORTED" }, "Nested, dynamic, ambiguous or unavailable macro execution remains unknown; no recursive expansion is performed.");
                if targets.is_empty()
                    && has_reference(&run.section.rows[index].dll_function)
                    && !has_reference(&name)
                    && self
                        .analysis
                        .source_files
                        .iter()
                        .any(|file| file.name.eq_ignore_ascii_case("MACRO_LIST.ini"))
                {
                    self.resolver.diagnostics.push(BundleDiagnostic::new("control_flow", "MACRO_TARGET_MISSING", "Resolved macro target has no implementation in supplied MACRO_LIST.ini.")
                        .at(&run.section.source, run.section.rows[index].line, Some(&run.section.name), Some(&run.section.rows[index].label_raw)).field("function", None));
                }
                self.deferred_calls.push((source, name));
                self.edge(source, pass, "macro_success", true);
                self.edge(source, fail, "macro_failure", true);
            } else {
                for (target, token, is_pass) in [
                    (pass, pass_path.as_str(), true),
                    (fail, fail_path.as_str(), false),
                ] {
                    let returning =
                        run.returns.is_some() && ["QUIT", "PASS", "FAIL", "END"].contains(&token);
                    let kind = if returning {
                        if token == "PASS" || token == "END" || (token == "QUIT" && is_pass) {
                            "macro_success"
                        } else {
                            "macro_failure"
                        }
                    } else if is_pass {
                        "pass"
                    } else {
                        "fail"
                    };
                    self.edge(source, target, kind, unknown_dispatch);
                }
            }
        }
    }

    fn loop_exhaustion(&mut self) {
        let mut outgoing = vec![Vec::new(); self.execution.len()];
        for &(source, target, unknown) in &self.links {
            if !unknown {
                outgoing[source].push(target);
            }
        }
        let mut steps = 0;
        for &(source, target) in &self.loop_failures {
            let mut pending = vec![target];
            let mut visited = HashSet::new();
            while let Some(current) = pending.pop() {
                if !visited.insert(current) {
                    continue;
                }
                let row = &self.execution[source];
                steps += outgoing[current].len() + 1;
                let issue = if steps > MAX_CYCLE_STEPS {
                    Some((
                        "LOOP_ANALYSIS_LIMIT",
                        "Loop re-entry analysis reached 65536 steps; remaining termination checks are incomplete.",
                    ))
                } else if current == source {
                    Some((
                        "LOOP_EXHAUSTION_UNCHECKED",
                        "A loop controller's failure path re-enters its resolved cycle after its budget may be exhausted; termination is unproven.",
                    ))
                } else {
                    None
                };
                if let Some((code, message)) = issue {
                    self.resolver.diagnostics.push(
                        BundleDiagnostic::new("control_flow", code, message)
                            .at(&row.file, row.line, Some(&row.section), Some(&row.row))
                            .field("fail_path", None)
                            .unchecked(),
                    );
                    if steps > MAX_CYCLE_STEPS {
                        return;
                    }
                    break;
                }
                pending.extend(outgoing[current].iter().copied());
            }
        }
    }

    fn reachability(&mut self, entry: Option<usize>) {
        let mut outgoing = vec![Vec::new(); self.execution.len()];
        for &(source, target, unknown) in &self.links {
            outgoing[source].push((target, unknown));
        }
        let mut queue = VecDeque::new();
        if let Some(entry) = entry {
            queue.push_back((entry, false));
        }
        let mut visited = HashSet::new();
        while let Some((index, unknown)) = queue.pop_front() {
            if !visited.insert((index, unknown)) {
                continue;
            }
            if !unknown {
                self.execution[index].reachability = "reachable";
            } else if self.execution[index].reachability != "reachable" {
                self.execution[index].reachability = "unknown";
            }
            queue.extend(
                outgoing[index]
                    .iter()
                    .map(|(target, edge_unknown)| (*target, unknown || *edge_unknown)),
            );
        }
    }
}

fn named_arguments(value: &str) -> Arguments {
    if value.eq_ignore_ascii_case("NULL") {
        return Arguments::Named(HashMap::new());
    }
    let mut arguments = HashMap::new();
    for entry in value.split('&') {
        let Some((name, value)) = entry.split_once('=') else {
            return Arguments::Unsupported;
        };
        if name.trim().is_empty() {
            return Arguments::Unsupported;
        }
        if arguments
            .insert(name.trim().to_ascii_lowercase(), value.into())
            .is_some()
        {
            return Arguments::Ambiguous;
        }
    }
    Arguments::Named(arguments)
}

#[derive(Clone, Copy)]
struct ReferenceSite<'a> {
    file: &'a str,
    section: &'a str,
    line: usize,
    row: &'a str,
}

struct Resolver<'a, 'b> {
    data: HashMap<String, Vec<&'a DataSection>>,
    diagnostics: &'b mut Vec<BundleDiagnostic>,
    steps: usize,
    bytes: usize,
    dynamic: HashSet<String>,
    runtime_sections: HashSet<String>,
    runtime_keys: HashMap<String, HashSet<String>>,
    runtime_writes_unknown: bool,
    bindings: Option<Bindings>,
    sensitive_tokens: HashSet<String>,
    resolved_secrets: HashSet<String>,
}

impl Resolver<'_, '_> {
    fn index_runtime_writes(&mut self, analysis: &AnalysisOutput) {
        let findings_before_classification = self.diagnostics.len();
        let mut unknown_writer = None;
        for _ in 0..2 {
            for section in &analysis.script_sections {
                for row in &section.rows {
                    let (function, function_known) =
                        self.resolve(&row.dll_function, section, row, "function");
                    let known_writer = function.eq_ignore_ascii_case("SFIS_TO_VAR")
                        || function.eq_ignore_ascii_case("RECORD_TESTRESULT");
                    if function_known && !known_writer {
                        continue;
                    }
                    let (device, device_known) =
                        self.resolve(&row.dll_name, section, row, "device");
                    let (parameters, parameters_known) =
                        self.resolve(&row.criteria, section, row, "parameters");
                    if !function_known || !parameters_known || !device_known {
                        self.runtime_writes_unknown = true;
                        unknown_writer.get_or_insert_with(|| {
                        BundleDiagnostic::new("references", "RUNTIME_WRITER_UNCHECKED", "Runtime write identity depends on unavailable invocation or runtime values; supplied variable values cannot be verified.")
                            .at(&section.source, row.line, Some(&section.name), Some(&row.label_raw))
                            .unchecked()
                    });
                        continue;
                    }
                    if function.eq_ignore_ascii_case("SFIS_TO_VAR") {
                        self.runtime_sections.extend(
                            parameters
                                .split(['&', ',', ';'])
                                .map(str::trim)
                                .filter(|name| {
                                    !name.is_empty()
                                        && !name.eq_ignore_ascii_case("NULL")
                                        && !name.contains(['=', '*'])
                                })
                                .map(str::to_ascii_lowercase),
                        );
                    } else if parameters.split(['&', ';', ',']).any(|entry| {
                        entry
                            .split_once('=')
                            .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("RECORD_TIMES"))
                    }) && let Some(name) = device
                        .split('#')
                        .next()
                        .and_then(|name| name.trim().strip_prefix("DLL"))
                    {
                        let name = name.trim_start_matches('_');
                        if !name.is_empty() {
                            self.runtime_keys
                                .entry(format!("dll_{name}").to_ascii_lowercase())
                                .or_default()
                                .insert("record_times".into());
                        }
                    }
                }
            }
        }
        self.diagnostics.truncate(findings_before_classification);
        if let Some(issue) = unknown_writer {
            self.diagnostics.push(issue);
        }
    }

    fn issue(&mut self, site: ReferenceSite<'_>, field: &str, code: &str, unsupported: bool) {
        let mut issue = BundleDiagnostic::new(
            "references",
            code,
            "Reference could not be statically verified from supplied contents.",
        )
        .at(site.file, site.line, Some(site.section), Some(site.row))
        .field(field, None);
        if unsupported {
            issue = issue.unchecked();
        }
        self.diagnostics.push(issue);
    }

    fn resolve(
        &mut self,
        value: &str,
        section: &ScriptSection,
        row: &ScriptRow,
        field: &str,
    ) -> (String, bool) {
        self.resolve_at(
            value,
            ReferenceSite {
                file: &section.source,
                section: &section.name,
                line: row.line,
                row: &row.label_raw,
            },
            field,
        )
    }

    fn resolve_at(&mut self, value: &str, site: ReferenceSite<'_>, field: &str) -> (String, bool) {
        let mut output = String::new();
        let mut rest = value;
        let mut complete = true;
        while let Some(start) = reference_start(rest) {
            output.push_str(&rest[..start]);
            rest = &rest[start..];
            self.steps += 1;
            if self.steps > MAX_REFERENCE_STEPS || self.bytes > MAX_TOTAL_RESOLVED_BYTES {
                self.issue(site, field, "REFERENCE_LIMIT", true);
                return (value.into(), false);
            }
            let Some(end) = rest.find('#') else {
                self.issue(site, field, "REFERENCE_MALFORMED", false);
                return (value.into(), false);
            };
            let token = &rest[..=end];
            let Some(spec) = rest.get(3..end) else {
                self.issue(site, field, "REFERENCE_MALFORMED", false);
                return (value.into(), false);
            };
            if spec.contains('*') {
                self.issue(site, field, "REFERENCE_NESTED_UNSUPPORTED", true);
                return (value.into(), false);
            }
            let replacement = if spec.trim().is_empty()
                || spec
                    .split_once('-')
                    .is_some_and(|(header, key)| header.trim().is_empty() || key.trim().is_empty())
            {
                self.issue(site, field, "REFERENCE_MALFORMED", false);
                None
            } else if self.dynamic.contains(&token.to_ascii_lowercase())
                || self.runtime_sections.contains(
                    &spec
                        .split_once('-')
                        .map_or(spec, |(header, _)| header)
                        .to_ascii_lowercase(),
                )
            {
                self.issue(site, field, "RUNTIME_VALUE_UNCHECKED", true);
                None
            } else if !rest.starts_with("*V:") {
                self.issue(
                    site,
                    field,
                    if ["*E:", "*I:", "*T:"]
                        .iter()
                        .any(|prefix| rest.starts_with(prefix))
                    {
                        "RUNTIME_REFERENCE_UNCHECKED"
                    } else {
                        "REFERENCE_PREFIX_UNSUPPORTED"
                    },
                    true,
                );
                None
            } else {
                self.lookup(spec, site, field)
            };
            if let Some(replacement) = replacement {
                if self.sensitive_tokens.contains(token) {
                    self.resolved_secrets.insert(replacement.clone());
                }
                self.bytes += replacement.len();
                if self.bytes > MAX_TOTAL_RESOLVED_BYTES {
                    self.issue(site, field, "REFERENCE_LIMIT", true);
                    return (value.into(), false);
                }
                output.push_str(&replacement);
            } else {
                output.push_str(token);
                complete = false;
            }
            if output.len() > MAX_RESOLVED_BYTES {
                self.issue(site, field, "REFERENCE_LIMIT", true);
                return (value.into(), false);
            }
            rest = &rest[end + 1..];
        }
        output.push_str(rest);
        if output.len() > MAX_RESOLVED_BYTES {
            self.issue(site, field, "REFERENCE_LIMIT", true);
            return (value.into(), false);
        }
        (output, complete)
    }

    fn lookup(&mut self, spec: &str, site: ReferenceSite<'_>, field: &str) -> Option<String> {
        let (header, key) = spec
            .split_once('-')
            .map_or((spec, None), |(header, key)| (header, Some(key)));
        if self
            .runtime_keys
            .get(&header.trim().to_ascii_lowercase())
            .is_some_and(|keys| {
                key.is_none_or(|key| keys.contains(&key.trim().to_ascii_lowercase()))
            })
        {
            self.issue(site, field, "RUNTIME_VALUE_UNCHECKED", true);
            return None;
        }
        if header.eq_ignore_ascii_case("Macro") {
            let (value, code, unsupported) = match (
                self.bindings.as_ref(),
                key.and_then(|key| key.split_once('_')),
            ) {
                (Some(bindings), Some((kind, name))) => {
                    let arguments = if kind.eq_ignore_ascii_case("Param") {
                        &bindings.params
                    } else if kind.eq_ignore_ascii_case("Criteria") {
                        &bindings.criteria
                    } else {
                        self.issue(site, field, "MACRO_ARGUMENT_CONTRACT_UNSUPPORTED", true);
                        return None;
                    };
                    match arguments {
                        Arguments::Named(arguments) => (
                            arguments.get(&name.to_ascii_lowercase()).cloned(),
                            "MACRO_ARGUMENT_MISSING",
                            false,
                        ),
                        Arguments::Ambiguous => (None, "MACRO_ARGUMENT_AMBIGUOUS", false),
                        Arguments::Unsupported => {
                            (None, "MACRO_ARGUMENT_CONTRACT_UNSUPPORTED", true)
                        }
                    }
                }
                _ => (None, "MACRO_ARGUMENT_UNBOUND", true),
            };
            if value.as_ref().is_some_and(|value| value.contains('*')) {
                self.issue(site, field, "MACRO_ARGUMENT_DYNAMIC", true);
                return None;
            }
            if value.is_none() {
                self.issue(site, field, code, unsupported);
            }
            return value;
        }
        if self.runtime_writes_unknown {
            self.issue(site, field, "RUNTIME_VALUE_UNCHECKED", true);
            return None;
        }
        if header.trim().is_empty() || key.is_some_and(|key| key.trim().is_empty()) {
            self.issue(site, field, "REFERENCE_MALFORMED", false);
            return None;
        }
        let Some(matches) = self.data.get(&header.trim().to_ascii_lowercase()) else {
            self.issue(site, field, "REFERENCE_SECTION_MISSING", false);
            return None;
        };
        if matches.len() != 1 {
            self.issue(site, field, "REFERENCE_AMBIGUOUS", false);
            return None;
        }
        let entries: Vec<_> = matches[0]
            .entries
            .iter()
            .filter(|entry| key.is_none_or(|key| entry.key.eq_ignore_ascii_case(key.trim())))
            .collect();
        if entries.is_empty() {
            self.issue(site, field, "REFERENCE_KEY_MISSING", false);
            return None;
        }
        let mut keys = HashSet::new();
        if entries
            .iter()
            .any(|entry| !keys.insert(entry.key.to_ascii_lowercase()))
        {
            self.issue(site, field, "REFERENCE_AMBIGUOUS", false);
            return None;
        }
        if entries
            .iter()
            .map(|entry| entry.key.len() + entry.value.len() + 2)
            .sum::<usize>()
            > MAX_RESOLVED_BYTES
        {
            self.issue(site, field, "REFERENCE_LIMIT", true);
            return None;
        }
        let value = if key.is_some() {
            entries[0].value.clone()
        } else {
            entries
                .iter()
                .map(|entry| format!("{}={}", entry.key, entry.value))
                .collect::<Vec<_>>()
                .join("&")
        };
        if has_reference(&value) {
            self.issue(site, field, "REFERENCE_INDIRECT_UNSUPPORTED", true);
            None
        } else {
            Some(value)
        }
    }
}
