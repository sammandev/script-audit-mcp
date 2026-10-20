use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Engine, Result};

use super::{
    BundleReport, CheckStatus, ExecutionRow, MAX_TEXT_BYTES, ValidateBundleRequest, invalid_request,
};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComparePlanRequest {
    pub bundle: ValidateBundleRequest,
    pub plan: StructuredPlan,
    pub flow_variant: FlowVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowVariant {
    Normal,
    Sampling,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructuredPlan {
    pub controlling_source: String,
    pub station: String,
    pub sources: Vec<PlanSource>,
    pub requirements: Vec<Requirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_policy: Option<SamplingPolicy>,
    #[serde(default)]
    pub conflicts: Vec<SourceConflict>,
    #[serde(default)]
    pub exceptions: Vec<EngineeringException>,
    #[serde(default)]
    pub unresolved_questions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingPolicy {
    pub rate: Option<Quantity>,
    pub schedule: Option<String>,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceConflict {
    pub id: String,
    pub requirement_id: String,
    pub kind: ConflictKind,
    pub statements: Vec<SourceStatement>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    WithinSource,
    PlanExample,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceStatement {
    pub provenance: Provenance,
    pub test: TxTest,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineeringException {
    pub id: String,
    pub conflict_id: String,
    pub requirement_id: String,
    pub station: String,
    pub source_revisions: BTreeMap<String, String>,
    pub decision: TxTest,
    pub rationale: String,
    pub approver: String,
    pub approval_evidence: String,
}

#[derive(Debug, Serialize)]
pub struct ConflictResult {
    pub conflict: SourceConflict,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanSource {
    pub id: String,
    pub revision: String,
    pub kind: SourceKind,
    pub approved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    TestPlan,
    Prompt,
    Example,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_id: String,
    pub revision: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub excerpt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    Mandatory,
    Sampling,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub provenance: Vec<Provenance>,
    pub applicability: Applicability,
    pub test: TxTest,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub unresolved_questions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TxTest {
    pub technology: Option<String>,
    pub purpose: Option<String>,
    pub band: Option<String>,
    pub standard: Option<String>,
    pub channel: Option<u32>,
    pub frequency: Option<Quantity>,
    pub bandwidth: Option<Quantity>,
    pub rate: Option<String>,
    pub chains: Option<Chains>,
    pub power_target: Option<Quantity>,
    pub power_tolerance: Option<Tolerance>,
    pub frequency_offset: Option<Tolerance>,
    pub evm: Option<Comparison>,
    pub packet_count: Option<u32>,
    pub input_level: Option<Quantity>,
    pub per: Option<Comparison>,
    pub rssi_tolerance: Option<Tolerance>,
    pub procedure: Option<Procedure>,
    pub calibration_interval: Option<Quantity>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Procedure {
    pub device: String,
    pub function: String,
    pub parameters: String,
    pub criteria: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Quantity {
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tolerance {
    pub lower: f64,
    pub upper: f64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Chains {
    PerChain(Vec<u32>),
    Bitmask(u32),
    Count(u32),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub operator: Operator,
    pub threshold: Quantity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

#[derive(Debug, Serialize)]
pub struct CoverageCase {
    pub requirement_id: String,
    pub applicability: Applicability,
    pub provenance: Vec<Provenance>,
    pub test: TxTest,
    pub depends_on: Vec<String>,
    pub status: &'static str,
    pub evidence: Vec<ScriptEvidence>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScriptEvidence {
    pub execution_id: String,
    pub call_site: Option<String>,
    pub file: String,
    pub line: usize,
    pub section: String,
    pub row: String,
}

#[derive(Debug, Default, Serialize)]
pub struct CoverageCount {
    pub total: usize,
    pub matched: usize,
}

#[derive(Debug, Serialize)]
pub struct PlanReport {
    pub status: CheckStatus,
    pub ready_for_review: bool,
    pub interpretation_verification: &'static str,
    pub station: String,
    pub controlling_source: String,
    pub sources: Vec<PlanSource>,
    pub flow_variant: FlowVariant,
    pub mandatory: CoverageCount,
    pub sampling: CoverageCount,
    pub sampling_policy: serde_json::Value,
    pub coverage: Vec<CoverageCase>,
    pub additional: Vec<ScriptEvidence>,
    pub conflicts: Vec<ConflictResult>,
    pub exceptions: Vec<EngineeringException>,
    pub blockers: Vec<String>,
    pub validation: BundleReport,
}

impl ComparePlanRequest {
    pub fn check_bounds(&self) -> Result<()> {
        self.bundle.check_bounds()?;
        let plan_bytes = serde_json::to_vec(&self.plan)
            .map_err(|_| invalid_request("structured plan cannot be represented"))?
            .len();
        let bundle_bytes = self
            .bundle
            .files
            .iter()
            .map(|file| file.name.len() + file.text.len())
            .sum::<usize>()
            + self.bundle.selected_flow.len()
            + self.bundle.device_scope.as_ref().map_or(0, String::len)
            + self
                .bundle
                .sensitive_values
                .iter()
                .map(String::len)
                .sum::<usize>()
            + self
                .bundle
                .runtime_bindings
                .iter()
                .map(|binding| {
                    binding.reference.len() + binding.value.as_ref().map_or(0, String::len)
                })
                .sum::<usize>();
        if plan_bytes + bundle_bytes > MAX_TEXT_BYTES
            || self.plan.sources.len() > 32
            || self.plan.requirements.len() > 256
            || self.plan.conflicts.len() > 128
            || self.plan.exceptions.len() > 128
            || self.plan.sampling_policy.as_ref().is_some_and(|policy| {
                policy.provenance.len() > 32
                    || policy
                        .schedule
                        .as_ref()
                        .is_some_and(|value| value.len() > 4096)
                    || policy
                        .rate
                        .as_ref()
                        .is_some_and(|rate| rate.unit.len() > 256)
            })
            || self
                .plan
                .conflicts
                .iter()
                .any(|conflict| conflict.statements.len() > 32)
            || self
                .plan
                .exceptions
                .iter()
                .any(|exception| exception.source_revisions.len() > 32)
            || self.plan.unresolved_questions.len() > 128
            || self.plan.requirements.iter().any(|requirement| {
                requirement.provenance.len() > 32
                    || requirement.depends_on.len() > 64
                    || requirement.unresolved_questions.len() > 128
                    || !bounded_test(&requirement.test)
            })
            || self
                .plan
                .conflicts
                .iter()
                .flat_map(|conflict| &conflict.statements)
                .any(|statement| !bounded_test(&statement.test))
            || self
                .plan
                .exceptions
                .iter()
                .any(|exception| !bounded_test(&exception.decision))
        {
            return Err(invalid_request("plan exceeds the structured input budget"));
        }
        let mut ids = HashSet::new();
        if self.plan.sources.iter().any(|source| {
            source.id.trim().is_empty()
                || source.id.len() > 128
                || source.revision.len() > 256
                || !ids.insert(&source.id)
        }) {
            return Err(invalid_request("source IDs must be nonempty and unique"));
        }
        ids.clear();
        if self.plan.requirements.iter().any(|requirement| {
            requirement.id.trim().is_empty()
                || requirement.id.len() > 128
                || !ids.insert(&requirement.id)
        }) {
            return Err(invalid_request(
                "requirement IDs must be nonempty and unique",
            ));
        }
        let requirement_ids = ids.clone();
        ids.clear();
        if self.plan.conflicts.iter().any(|conflict| {
            conflict.id.trim().is_empty()
                || !ids.insert(&conflict.id)
                || !requirement_ids.contains(&conflict.requirement_id)
                || conflict.statements.len() < 2
        }) {
            return Err(invalid_request(
                "conflicts need unique IDs, an existing requirement, and at least two sourced statements",
            ));
        }
        ids.clear();
        if self
            .plan
            .exceptions
            .iter()
            .any(|exception| exception.id.trim().is_empty() || !ids.insert(&exception.id))
        {
            return Err(invalid_request("exception IDs must be nonempty and unique"));
        }
        Ok(())
    }
}

pub fn compare(request: ComparePlanRequest, engine: &Engine) -> Result<serde_json::Value> {
    compare_with_secrets(request, engine, &[]).map(|(report, _)| report)
}

pub(super) fn compare_with_secrets(
    request: ComparePlanRequest,
    engine: &Engine,
    declared_secrets: &[String],
) -> Result<(serde_json::Value, Vec<String>)> {
    request.check_bounds()?;
    let (validation, secrets) =
        super::validate_with_secrets(request.bundle, engine, declared_secrets)?;
    let mut blockers = request.plan.unresolved_questions.clone();
    let sampling_policy =
        assess_sampling_policy(&request.plan, request.flow_variant, &mut blockers);
    if validation.status != CheckStatus::Valid {
        blockers.push("Bundle validation has invalid or incomplete checks; inspect validation layers and located diagnostics.".into());
    }
    if request.plan.station.trim().is_empty() {
        blockers.push("Station identity is missing.".into());
    }
    if !request.plan.sources.iter().any(|source| {
        source.id == request.plan.controlling_source
            && source.approved
            && source.kind != SourceKind::Example
            && !source.revision.trim().is_empty()
    }) {
        blockers.push("Controlling approved plan/prompt source and revision are required.".into());
    }
    if request.plan.requirements.is_empty() {
        blockers.push("No sourced requirements were supplied.".into());
    }
    let (conflicts, decisions) = resolve_conflicts(&request.plan, &mut blockers);
    let mut mandatory = CoverageCount::default();
    let mut sampling = CoverageCount::default();
    let measurements: Vec<_> = validation
        .execution
        .iter()
        .filter(|row| {
            row.reachability != "unreachable" && !row.device.eq_ignore_ascii_case("MACRO")
        })
        .map(Measurement::new)
        .collect();
    let mut used = HashSet::new();
    let mut witnesses = BTreeMap::new();
    let mut comparisons = 0;
    let mut coverage: Vec<_> = request.plan.requirements.iter().filter(|requirement| {
        requirement.applicability == Applicability::Mandatory || request.flow_variant == FlowVariant::Sampling
    }).map(|requirement| {
        match requirement.applicability {
            Applicability::Mandatory => mandatory.total += 1,
            Applicability::Sampling => sampling.total += 1,
        }
        let test = decisions.get(&requirement.id).unwrap_or(&requirement.test);
        let mut case = CoverageCase {
            requirement_id: requirement.id.clone(),
            applicability: requirement.applicability,
            provenance: requirement.provenance.clone(),
            test: test.clone(),
            depends_on: requirement.depends_on.clone(),
            status: "missing",
            evidence: Vec::new(),
            reasons: Vec::new(),
        };
        let mut matches = Candidates::default();
        let mut partials = Vec::new();
        let mut mismatches = Candidates::default();
        let mut unknown = Candidates::default();
        let mut budget_exhausted = false;
        for measurement in &measurements {
            if !measurement.is_candidate(test) {
                continue;
            }
            comparisons += 1;
            if comparisons > 65_536 {
                budget_exhausted = true;
                unknown.push(measurement.row, vec!["Plan comparison budget reached.".into()]);
                break;
            }
            let unaudited = validation.diagnostics.iter().any(|issue| {
                issue.file.as_deref() == Some(&measurement.row.file)
                    && issue.line == Some(measurement.row.line)
                    && matches!(issue.severity, "error" | "unsupported")
                    && issue.evidence.as_deref().and_then(|evidence| evidence.strip_prefix("execution="))
                        .is_none_or(|evidence| evidence.split(';').next() == Some(measurement.row.id.as_str()))
            });
            if !unaudited && measurement.unrelated_to(test) {
                continue;
            }
            let (mut status, mut reasons) = measurement.compare(test);
            if unaudited {
                status = "unknown";
                reasons.push("This execution row has invalid or unsupported validation checks.".into());
            }
            match status {
                "matched" => matches.push(measurement.row, reasons),
                "partial" => partials.push(measurement.row),
                "conflicting" => mismatches.push(measurement.row, reasons),
                _ => unknown.push(measurement.row, reasons),
            }
        }
        if let Some(Chains::PerChain(expected)) = &test.chains {
            let masks: HashSet<_> = partials.iter().flat_map(|row| antenna_masks(row)).collect();
            if !partials.is_empty() && expected.iter().all(|mask| masks.contains(mask)) {
                let mut witnessed = HashSet::new();
                for row in partials {
                    let witnesses: Vec<_> = antenna_masks(row).into_iter()
                        .filter(|mask| expected.contains(mask)).collect();
                    if witnesses.into_iter().any(|mask| witnessed.insert(mask)) {
                        matches.push(row, Vec::new());
                    } else {
                        matches.rows.push(row);
                    }
                }
            } else {
                for row in partials {
                    mismatches.push(row, vec!["Individual antenna-chain coverage is incomplete.".into()]);
                }
            }
        }
        let candidates = if !matches.rows.is_empty() {
            case.status = "matched";
            matches
        } else if !mismatches.rows.is_empty() {
            case.status = "conflicting";
            mismatches
        } else if !unknown.rows.is_empty() {
            case.status = "unknown";
            unknown
        } else {
            case.reasons.push("No related reachable measurement was found.".into());
            Candidates::default()
        };
        let mut candidate_ids = Vec::new();
        for row in candidates.rows {
            used.insert(row.id.clone());
            candidate_ids.push(row.id.clone());
        }
        for (row, reasons) in candidates.evidence {
            case.evidence.push(evidence(row));
            case.reasons.extend(reasons);
        }
        if budget_exhausted {
            if case.status != "conflicting" { case.status = "unknown"; }
            case.reasons.push("Plan comparison budget reached; this requirement was not fully analyzed.".into());
        }
        case.reasons.extend(requirement.unresolved_questions.clone());
        if !reviewed_requirement_provenance(&request.plan, &requirement.provenance) {
            case.reasons.push("Requirement needs current controlling-source provenance with a location or excerpt.".into());
        }
        if test.calibration_interval.is_some() {
            case.reasons.push("The sourced calibration interval is retained; operator scheduling and calibration history remain unchecked. Script structure cannot establish that the interval was observed.".into());
        }
        if conflicts.iter().any(|conflict| conflict.conflict.requirement_id == requirement.id && conflict.resolved_by.is_none()) {
            case.status = "conflicting";
            case.reasons.push("Unresolved sourced statements disagree; examples do not override the approved plan.".into());
        }
        if case.status == "matched" && !case.reasons.is_empty() {
            case.status = "unknown";
        }
        if case.status == "matched" {
            witnesses.insert(requirement.id.clone(), candidate_ids);
        }
        case
    }).collect();
    let bluetooth_setups: HashSet<_> = coverage
        .iter()
        .filter(|case| is_bluetooth_setup(&case.test))
        .map(|case| case.requirement_id.clone())
        .collect();
    for case in &mut coverage {
        if case.status == "matched"
            && case.test.technology.as_deref() == Some("bluetooth")
            && matches!(case.test.purpose.as_deref(), Some("tx" | "rx"))
            && !case
                .depends_on
                .iter()
                .any(|dependency| bluetooth_setups.contains(dependency))
        {
            case.status = "unknown";
            case.reasons.push("Bluetooth requires a declared TECH=BT setup prerequisite; IOT alone does not identify the radio technology.".into());
        }
    }
    check_dependencies(&mut coverage, &witnesses, &validation);
    for case in &coverage {
        if case.status == "matched" {
            match case.applicability {
                Applicability::Mandatory => mandatory.matched += 1,
                Applicability::Sampling => sampling.matched += 1,
            }
        } else {
            blockers.push(format!(
                "{}: {} coverage.",
                case.requirement_id, case.status
            ));
        }
    }
    let additional = measurements
        .iter()
        .filter(|measurement| measurement.is_supported() && !used.contains(&measurement.row.id))
        .map(|measurement| evidence(measurement.row))
        .collect();
    let status = if validation.status == CheckStatus::Invalid
        || coverage.iter().any(|case| case.status == "conflicting")
    {
        CheckStatus::Invalid
    } else if validation.status == CheckStatus::Incomplete || !blockers.is_empty() {
        CheckStatus::Incomplete
    } else {
        CheckStatus::Valid
    };
    let report = PlanReport {
        status,
        ready_for_review: status == CheckStatus::Valid,
        interpretation_verification: "unchecked_client_interpretation",
        station: request.plan.station,
        controlling_source: request.plan.controlling_source,
        sources: request.plan.sources,
        flow_variant: request.flow_variant,
        mandatory,
        sampling,
        sampling_policy,
        coverage,
        additional,
        conflicts,
        exceptions: request.plan.exceptions,
        blockers,
        validation,
    };
    let mut report = serde_json::to_value(report)
        .map_err(|_| invalid_request("comparison report cannot be represented"))?;
    let validation = report["validation"].take();
    redact_summary(&mut report, &secrets);
    report["validation"] = validation;
    Ok((report, secrets))
}

fn assess_sampling_policy(
    plan: &StructuredPlan,
    variant: FlowVariant,
    blockers: &mut Vec<String>,
) -> serde_json::Value {
    if variant == FlowVariant::Normal {
        return serde_json::json!({"status":"not_applicable","requirements":null,
            "runtime_application":"unchecked_not_encoded"});
    }
    let policy = plan.sampling_policy.as_ref();
    let sourced = policy.is_some_and(|policy| {
        policy
            .rate
            .as_ref()
            .is_some_and(|rate| rate.unit == "%" && rate.value > 0.0 && rate.value <= 100.0)
            && policy
                .schedule
                .as_ref()
                .is_some_and(|schedule| !schedule.trim().is_empty())
            && !policy.provenance.is_empty()
            && policy.provenance.iter().all(|evidence| {
                evidence.source_id == plan.controlling_source
                    && (!evidence.location.trim().is_empty() || !evidence.excerpt.trim().is_empty())
                    && plan.sources.iter().any(|source| {
                        source.id == evidence.source_id
                            && source.revision == evidence.revision
                            && source.approved
                            && source.kind != SourceKind::Example
                            && !source.revision.trim().is_empty()
                    })
            })
    });
    if sourced {
        blockers.push("Sampling policy application remains unsupported: supply an audited scheduler encoding or approved operator-applied contract and verify it off-machine; sourced policy alone cannot establish readiness.".into());
    } else {
        blockers.push("Supply approved sampling rate and schedule requirements (rate > 0 and <= 100 percent, nonempty schedule) with current controlling-source provenance; no production policy will be invented.".into());
    }
    serde_json::json!({"status":if sourced {"sourced_requirements"} else {"unresolved"},
        "requirements":policy,"runtime_application":"unchecked_not_encoded"})
}

fn check_dependencies(
    coverage: &mut [CoverageCase],
    witnesses: &BTreeMap<String, Vec<String>>,
    validation: &BundleReport,
) {
    let indices: HashMap<_, _> = coverage
        .iter()
        .enumerate()
        .map(|(index, case)| (case.requirement_id.clone(), index))
        .collect();
    let mut graph: HashMap<&str, Vec<_>> = HashMap::new();
    let rows: HashMap<_, _> = validation
        .execution
        .iter()
        .map(|row| (row.id.as_str(), row))
        .collect();
    for edge in &validation.execution_edges {
        graph.entry(&edge.source).or_default().push(edge);
    }
    let mut budget = 262_144_usize;
    for index in 0..coverage.len() {
        if coverage[index].status != "matched" {
            continue;
        }
        for dependency in coverage[index].depends_on.clone() {
            let result = if let Some(&prerequisite) = indices.get(&dependency) {
                if coverage[prerequisite].status != "matched" {
                    (
                        if matches!(coverage[prerequisite].status, "missing" | "conflicting") {
                            "conflicting"
                        } else {
                            "unknown"
                        },
                        "Prerequisite has no complete matching structural evidence.",
                    )
                } else if let (Some(required), Some(consumers), Some(entry)) = (
                    witnesses.get(&dependency),
                    witnesses.get(&coverage[index].requirement_id),
                    validation.execution.first(),
                ) {
                    let group_count = match &coverage[prerequisite].test.chains {
                        Some(Chains::PerChain(masks)) => masks.len(),
                        _ => 1,
                    };
                    let grouping_cost = required.len() * group_count;
                    if grouping_cost > budget {
                        budget = 0;
                        (
                            "unknown",
                            "Dependency witness budget reached; success ordering is unproven.",
                        )
                    } else {
                        budget -= grouping_cost;
                        let groups: Vec<HashSet<_>> = if let Some(Chains::PerChain(masks)) =
                            &coverage[prerequisite].test.chains
                        {
                            masks
                                .iter()
                                .map(|mask| {
                                    required
                                        .iter()
                                        .filter(|id| {
                                            rows.get(id.as_str()).is_some_and(|row| {
                                                antenna_masks(row).contains(mask)
                                            })
                                        })
                                        .map(String::as_str)
                                        .collect()
                                })
                                .collect()
                        } else {
                            vec![required.iter().map(String::as_str).collect()]
                        };
                        let consumers: HashSet<_> = consumers.iter().map(String::as_str).collect();
                        let mut result = ("matched", "");
                        for required in groups {
                            let ordering = success_order(
                                &required,
                                &consumers,
                                entry,
                                &graph,
                                &rows,
                                &mut budget,
                            );
                            if ordering.0 != "matched" {
                                result = ordering;
                                if ordering.0 == "conflicting" {
                                    break;
                                }
                            }
                        }
                        result
                    }
                } else {
                    ("unknown", "Dependency execution evidence is unavailable.")
                }
            } else {
                (
                    "unknown",
                    "Dependency is not a declared requirement applicable to this flow.",
                )
            };
            if result.0 != "matched" {
                if coverage[index].status != "conflicting" {
                    coverage[index].status = result.0;
                }
                coverage[index]
                    .reasons
                    .push(format!("{dependency}: {}", result.1));
            }
        }
    }
    for index in 0..coverage.len() {
        if coverage[index].status != "matched"
            || coverage[index].test.technology.as_deref() != Some("bluetooth")
            || !matches!(coverage[index].test.purpose.as_deref(), Some("tx" | "rx"))
        {
            continue;
        }
        let required: HashSet<_> = coverage[index]
            .depends_on
            .iter()
            .filter(|dependency| {
                indices
                    .get(*dependency)
                    .is_some_and(|&prerequisite| is_bluetooth_setup(&coverage[prerequisite].test))
            })
            .filter_map(|dependency| witnesses.get(dependency))
            .flatten()
            .map(String::as_str)
            .collect();
        let consumers: HashSet<_> = witnesses
            .get(&coverage[index].requirement_id)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        for row in &validation.execution {
            if row.reachability == "unreachable"
                || !row
                    .device
                    .split('#')
                    .next()
                    .is_some_and(|device| device.eq_ignore_ascii_case("DLLIOT"))
                || !row.function.eq_ignore_ascii_case("DUT_INSERT")
                || row
                    .parameters
                    .split('&')
                    .any(|assignment| assignment == "TECH=BT")
            {
                continue;
            }
            if success_order(&required, &consumers, row, &graph, &rows, &mut budget).0 != "matched"
            {
                coverage[index].status = "unknown";
                coverage[index].reasons.push("A reachable IOT radio reselection or uncertain graph can reach this measurement without reestablishing its declared TECH=BT setup.".into());
                break;
            }
        }
    }
    for _ in 0..coverage.len() {
        let mut changed = false;
        for index in 0..coverage.len() {
            if coverage[index].status == "matched"
                && coverage[index].depends_on.iter().any(|dependency| {
                    indices
                        .get(dependency)
                        .is_none_or(|&prerequisite| coverage[prerequisite].status != "matched")
                })
            {
                coverage[index].status = "unknown";
                coverage[index]
                    .reasons
                    .push("A transitive prerequisite is not established.".into());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn success_order(
    required: &HashSet<&str>,
    consumers: &HashSet<&str>,
    entry: &ExecutionRow,
    graph: &HashMap<&str, Vec<&super::ExecutionEdge>>,
    rows: &HashMap<&str, &ExecutionRow>,
    budget: &mut usize,
) -> (&'static str, &'static str) {
    let mut queue = VecDeque::from([entry.id.as_str()]);
    let mut seen = HashSet::new();
    let mut uncertain = entry.reachability != "reachable";
    let mut bypass = false;
    while let Some(current) = queue.pop_front() {
        if !seen.insert(current) {
            continue;
        }
        if consumers.contains(current) {
            bypass = true;
            break;
        }
        for edge in graph.get(current).into_iter().flatten() {
            if *budget == 0 {
                uncertain = true;
                queue.clear();
                break;
            }
            *budget -= 1;
            if edge.certainty != "supported" || edge.target == "unknown" {
                uncertain = true;
            }
            let operation_success = edge.kind == "pass"
                || edge.kind == "macro_success"
                    && rows
                        .get(current)
                        .is_some_and(|row| !matches!(row.fail_path.as_str(), "PASS" | "END"));
            if required.contains(current) && operation_success {
                continue;
            }
            queue.push_back(&edge.target);
        }
    }
    if uncertain {
        (
            "unknown",
            "Dependency graph or analysis budget is incomplete; success ordering is unproven.",
        )
    } else if bypass {
        (
            "conflicting",
            "A reachable measurement/procedure can occur before successful completion of its prerequisite.",
        )
    } else {
        ("matched", "")
    }
}

pub(super) fn redact_summary(value: &mut serde_json::Value, secrets: &[String]) {
    match value {
        serde_json::Value::String(text) => *text = super::redact(text, secrets),
        serde_json::Value::Array(items) => {
            for item in items {
                redact_summary(item, secrets);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, mut value) in std::mem::take(fields) {
                if key == "source_revisions" {
                    if let serde_json::Value::Object(revisions) = &mut value {
                        for (source, mut revision) in std::mem::take(revisions) {
                            redact_summary(&mut revision, secrets);
                            revisions.insert(super::redact(&source, secrets), revision);
                        }
                    }
                } else if !matches!(
                    key.as_str(),
                    "status"
                        | "kind"
                        | "operator"
                        | "applicability"
                        | "flow_variant"
                        | "severity"
                        | "layer"
                        | "dialect"
                        | "runtime_verification"
                        | "runtime_application"
                        | "hardware_verification"
                        | "packaging"
                        | "interpretation_verification"
                        | "verification"
                        | "artifact_authority"
                        | "format"
                        | "export"
                        | "checksum"
                        | "input_identities"
                        | "draft_identity"
                ) {
                    redact_summary(&mut value, secrets);
                }
                fields.insert(key, value);
            }
        }
        _ => {}
    }
}

fn evidence(row: &ExecutionRow) -> ScriptEvidence {
    ScriptEvidence {
        execution_id: row.id.clone(),
        call_site: row.call_site.clone(),
        file: row.file.clone(),
        line: row.line,
        section: row.section.clone(),
        row: row.row.clone(),
    }
}

#[derive(Default)]
struct Candidates<'a> {
    rows: Vec<&'a ExecutionRow>,
    evidence: Vec<(&'a ExecutionRow, Vec<String>)>,
}

impl<'a> Candidates<'a> {
    fn push(&mut self, row: &'a ExecutionRow, reasons: Vec<String>) {
        self.rows.push(row);
        if self.evidence.len() < 64 {
            self.evidence.push((row, reasons));
        }
    }
}

struct Measurement<'a> {
    row: &'a ExecutionRow,
    parameters: BTreeMap<&'a str, &'a str>,
    criteria: BTreeMap<&'a str, &'a str>,
}

impl<'a> Measurement<'a> {
    fn new(row: &'a ExecutionRow) -> Self {
        let assignments = |text: &'a str| {
            text.split('&')
                .filter_map(|assignment| assignment.split_once('='))
                .collect()
        };
        Self {
            row,
            parameters: assignments(&row.parameters),
            criteria: assignments(&row.criteria),
        }
    }

    fn is_supported(&self) -> bool {
        matches!(
            self.row.function.as_str(),
            "TX_MULTI_VERIFICATION" | "TX_MULTI_VERIFY" | "RX_VERIFY_PER" | "BRCM_RSSI_CALIBRATION"
        ) || super::semantics::has_reference(&self.row.function)
            || super::semantics::has_reference(&self.row.device)
    }

    fn purpose(&self) -> Option<&'static str> {
        match self.row.function.as_str() {
            "TX_MULTI_VERIFICATION" | "TX_MULTI_VERIFY" => Some("tx"),
            "RX_VERIFY_PER" => Some("rx"),
            "BRCM_RSSI_CALIBRATION" => Some("calibration"),
            _ => None,
        }
    }

    fn is_candidate(&self, test: &TxTest) -> bool {
        if let Some(procedure) = &test.procedure {
            (self.row.device == procedure.device && self.row.function == procedure.function)
                || super::semantics::has_reference(&self.row.device)
                || super::semantics::has_reference(&self.row.function)
        } else {
            self.is_supported()
                && (test.technology.as_deref() != Some("bluetooth")
                    || test.band.is_some()
                    || self.row.device.split('#').next() == Some("DLLIOT")
                        && self.purpose() == test.purpose.as_deref()
                    || super::semantics::has_reference(&self.row.device)
                    || super::semantics::has_reference(&self.row.function))
        }
    }

    fn unrelated_to(&self, test: &TxTest) -> bool {
        if self.row.redacted
            || self.row.reachability != "reachable"
            || self.row.device.split('#').next() != Some("DLLWIFI_TEST")
            || self.purpose() != test.purpose.as_deref()
            || test.technology.as_deref() != Some("wifi")
            || test.band.as_deref() != Some("6G")
        {
            return false;
        }
        let different_rate = test.rate.as_ref().is_some_and(|expected| {
            self.parameters.get("DATA_RATE").is_some_and(|actual| {
                !super::semantics::has_reference(actual) && expected != actual
            })
        });
        let different_frequency = test.frequency.as_ref().is_some_and(|expected| {
            expected.unit == "MHz"
                && self
                    .parameters
                    .get("FREQ")
                    .and_then(|actual| quantity(actual, "MHz", true))
                    .is_some_and(|actual| expected.value != actual)
        });
        different_rate && different_frequency
    }

    fn compare(&self, test: &TxTest) -> (&'static str, Vec<String>) {
        if let Some(procedure) = &test.procedure {
            let mut remaining = test.clone();
            remaining.procedure = None;
            remaining.purpose = None;
            if is_bluetooth_setup(test)
                || test.technology.as_deref() == Some("bluetooth")
                    && matches!(test.purpose.as_deref(), Some("save" | "cleanup"))
            {
                remaining.technology = None;
            }
            if !matches!(test.purpose.as_deref(), Some("setup" | "save" | "cleanup"))
                || remaining != TxTest::default()
                || self.row.reachability != "reachable"
                || self.row.redacted
                || super::semantics::has_reference(&self.row.parameters)
                || super::semantics::has_reference(&self.row.criteria)
                || super::semantics::has_reference(&procedure.parameters)
                || super::semantics::has_reference(&procedure.criteria)
            {
                return (
                    "unknown",
                    vec![
                        "Declared procedure purpose, values, or reachability are unaudited.".into(),
                    ],
                );
            }
            return if self.row.device == procedure.device
                && self.row.function == procedure.function
                && self.row.parameters == procedure.parameters
                && self.row.criteria == procedure.criteria
            {
                ("matched", Vec::new())
            } else {
                (
                    "conflicting",
                    vec!["Declared procedure identity or payload differs.".into()],
                )
            };
        }
        let bluetooth = test.technology.as_deref() == Some("bluetooth");
        if !(bluetooth && matches!(test.purpose.as_deref(), Some("tx" | "rx"))
            || test.technology.as_deref() == Some("wifi")
                && matches!(test.purpose.as_deref(), Some("tx" | "rx" | "calibration"))
                && test.band.as_deref() == Some("6G"))
        {
            return ("unknown", vec!["Only explicitly specified 6 GHz Wi-Fi TX/RX/calibration and Bluetooth TX/RX requirements are audited in this comparison.".into()]);
        }
        if self.purpose() != test.purpose.as_deref() {
            return (
                "unknown",
                vec!["Function does not establish the required measurement purpose.".into()],
            );
        }
        if test.purpose.as_deref() == Some("tx")
            && (test.input_level.is_some() || test.per.is_some() || test.rssi_tolerance.is_some())
            || test.purpose.as_deref() != Some("tx")
                && (test.power_target.is_some()
                    || test.power_tolerance.is_some()
                    || test.evm.is_some())
        {
            return (
                "unknown",
                vec!["Measurement dimensions do not belong to the audited purpose.".into()],
            );
        }
        if self.row.redacted {
            return (
                "unknown",
                vec!["Redacted execution values cannot establish coverage.".into()],
            );
        }
        let mut mismatches = Vec::new();
        let mut unknown = Vec::new();
        let mut partial = false;
        if test.frequency_offset.is_some() && (!bluetooth || test.purpose.as_deref() != Some("tx"))
            || bluetooth
                && (test.evm.is_some()
                    || test.rssi_tolerance.is_some()
                    || test.band.is_some()
                    || test.standard.is_some()
                    || test.bandwidth.is_some()
                    || test.rate.is_some())
        {
            unknown.push(
                "Specified dimensions are outside the audited Bluetooth/Wi-Fi profile.".into(),
            );
        }
        let identity = self
            .row
            .device
            .split_once('#')
            .map_or(self.row.device.as_str(), |(base, _)| base);
        if identity != if bluetooth { "DLLIOT" } else { "DLLWIFI_TEST" }
            || bluetooth
                && !matches!(
                    self.row.function.as_str(),
                    "TX_MULTI_VERIFY" | "RX_VERIFY_PER"
                )
            || !bluetooth && self.row.function == "TX_MULTI_VERIFY"
            || self.purpose() != test.purpose.as_deref()
            || self.row.redacted
            || self.row.reachability != "reachable"
        {
            unknown
                .push("Function identity, redacted values, or reachability is unaudited.".into());
        }
        for (name, expected, actual) in [
            (
                "technology",
                test.technology.as_deref(),
                Some(if bluetooth { "bluetooth" } else { "wifi" }),
            ),
            ("purpose", test.purpose.as_deref(), self.purpose()),
            (
                "band",
                test.band.as_deref(),
                self.parameters.get("BAND").copied(),
            ),
            (
                "standard",
                test.standard.as_deref(),
                self.parameters.get("STANDARD").copied(),
            ),
            (
                "rate",
                test.rate.as_deref(),
                self.parameters.get("DATA_RATE").copied(),
            ),
        ] {
            if bluetooth && matches!(name, "band" | "standard" | "rate") {
                continue;
            }
            if test.purpose.as_deref() == Some("calibration")
                && expected.is_none()
                && name == "rate"
            {
                continue;
            }
            match (expected, actual) {
                (Some(expected), Some(actual)) if !super::semantics::has_reference(actual) => {
                    if expected != actual {
                        mismatches.push(format!(
                            "{name}: literal dimension differs from the requirement."
                        ));
                    }
                }
                _ => unknown.push(format!(
                    "{name}: a specified literal dimension is required."
                )),
            }
        }
        for (name, expected, actual, unit) in [
            (
                "frequency",
                test.frequency.as_ref(),
                self.parameters.get("FREQ").copied(),
                "MHz",
            ),
            (
                "bandwidth",
                test.bandwidth.as_ref(),
                self.parameters.get("BW").copied(),
                "MHz",
            ),
            (
                if test.purpose.as_deref() == Some("tx") {
                    "power_target"
                } else {
                    "input_level"
                },
                if test.purpose.as_deref() == Some("tx") {
                    test.power_target.as_ref()
                } else {
                    test.input_level.as_ref()
                },
                self.parameters
                    .get(if test.purpose.as_deref() == Some("tx") {
                        "TX_TARGET_POWER"
                    } else {
                        "RX_TARGET_POWER"
                    })
                    .copied(),
                "dBm",
            ),
        ] {
            if bluetooth && name == "bandwidth" {
                continue;
            }
            if test.purpose.as_deref() == Some("calibration") && expected.is_none() {
                continue;
            }
            let parsed = actual.and_then(|value| quantity(value, unit, unit == "MHz" || bluetooth));
            match (expected, parsed) {
                (Some(expected), Some(actual)) => {
                    if expected.unit != unit || expected.value != actual {
                        mismatches.push(format!(
                            "{name}: value or unit differs from the requirement."
                        ));
                    }
                }
                _ => unknown.push(format!(
                    "{name}: a specified literal quantity with audited units is required."
                )),
            }
        }
        if test.channel.is_some() {
            unknown.push("Channel/frequency conversion has not been audited.".into());
        }
        match (&test.chains, self.parameters.get("ANT")) {
            (Some(Chains::PerChain(expected)), Some(actual)) if !expected.is_empty() && expected.iter().all(|mask| matches!(mask, 1 | 2 | 4 | 8)) => {
                let masks: Option<Vec<u32>> = actual.split(',').map(|mask| mask.parse().ok()).collect();
                match masks {
                    Some(masks) if masks.iter().all(|mask| matches!(mask, 1 | 2 | 4 | 8)) => {
                        if !expected.iter().all(|mask| masks.contains(mask)) {
                            if expected.iter().any(|mask| masks.contains(mask)) {
                                partial = true;
                            } else {
                                mismatches.push("Individual antenna-chain coverage differs.".into());
                            }
                        }
                    }
                    Some(_) => mismatches.push("Composite antenna bitmasks do not establish per-chain coverage.".into()),
                    None => unknown.push("Antenna values are unresolved.".into()),
                }
            }
            (Some(Chains::Bitmask(expected)), Some(actual)) => {
                match actual.parse::<u32>() {
                    Ok(actual) if actual == *expected => {}
                    Ok(_) => mismatches.push("Antenna bitmask differs.".into()),
                    Err(_) => unknown.push("Antenna bitmask is unresolved or is a per-chain list.".into()),
                }
            }
            _ => unknown.push("Explicit audited per-chain masks or a literal composite bitmask are required; counts are not masks.".into()),
        }
        if let Some(expected) = &test.power_tolerance {
            match self.criteria.get("POWER").and_then(|value| {
                if bluetooth {
                    unit_tolerance(value, "dB", true)
                } else {
                    tolerance(value)
                }
            }) {
                Some(actual) if actual != *expected => {
                    mismatches.push("Power tolerance differs (dB, not dBm).".into())
                }
                Some(_) => {}
                None => unknown.push("Power tolerance semantics or units are unknown.".into()),
            }
        }
        if let Some(expected) = &test.frequency_offset {
            match self
                .criteria
                .get("FREQ_ERROR_KHZ")
                .and_then(|value| unit_tolerance(value, "kHz", true))
            {
                Some(actual) if actual != *expected => {
                    mismatches.push("Frequency-offset bounds or kHz unit differ.".into())
                }
                Some(_) => {}
                None => unknown.push("Frequency offset needs literal audited kHz bounds.".into()),
            }
        }
        if let Some(expected) = &test.evm {
            match self.criteria.get("EVM").and_then(|value| comparison(value, "dB")) {
                Some(actual) if actual != *expected => mismatches.push("EVM threshold, unit, or strict/inclusive operator differs.".into()),
                Some(_) => {}
                None => unknown.push("EVM needs an explicit audited comparison operator and dB unit; bare thresholds are unknown.".into()),
            }
        }
        if let Some(expected) = &test.per {
            match self.criteria.get("PER").and_then(|value| comparison(value, "%")) {
                Some(actual) if actual != *expected => mismatches.push("PER threshold, percent unit, or strict/inclusive operator differs.".into()),
                Some(_) => {}
                None => unknown.push("PER needs an explicit comparison operator and percent unit; bare thresholds are unknown.".into()),
            }
        } else if test.purpose.as_deref() == Some("rx") {
            unknown.push("RX requires a specified PER acceptance criterion.".into());
        }
        if let Some(expected) = &test.rssi_tolerance {
            match self.criteria.get("RSSI").and_then(|value| tolerance(value)) {
                Some(actual) if actual != *expected => {
                    mismatches.push("RSSI tolerance differs (dB, not dBm).".into())
                }
                Some(_) => {}
                None => unknown.push("RSSI tolerance semantics or units are unknown.".into()),
            }
        }
        if let Some(expected) = test.packet_count {
            match self
                .parameters
                .get("FRAME_COUNT")
                .and_then(|value| value.parse::<u32>().ok())
            {
                Some(actual) if actual != expected => {
                    mismatches.push("Packet count differs.".into())
                }
                Some(_) => {}
                None => unknown.push("Packet count is unresolved.".into()),
            }
        } else if test.purpose.as_deref() == Some("rx") {
            unknown.push("RX requires a specified packet count.".into());
        }
        if !mismatches.is_empty() {
            mismatches.extend(unknown);
            ("conflicting", mismatches)
        } else if !unknown.is_empty() {
            ("unknown", unknown)
        } else if partial {
            ("partial", Vec::new())
        } else {
            ("matched", Vec::new())
        }
    }
}

fn antenna_masks(row: &ExecutionRow) -> Vec<u32> {
    row.parameters
        .split('&')
        .find_map(|assignment| assignment.strip_prefix("ANT="))
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter_map(|mask| mask.parse().ok())
        .collect()
}

fn quantity(text: &str, unit: &str, implicit_unit: bool) -> Option<f64> {
    let number = text
        .strip_suffix(unit)
        .or(implicit_unit.then_some(text))?
        .parse::<f64>()
        .ok()?;
    number.is_finite().then_some(number)
}

fn tolerance(text: &str) -> Option<Tolerance> {
    unit_tolerance(text, "dB", false)
}

fn unit_tolerance(text: &str, unit: &str, implicit_unit: bool) -> Option<Tolerance> {
    let (lower, upper) = if let Some((lower, upper)) = text.split_once('~') {
        (
            quantity(lower, unit, true)?,
            quantity(upper, unit, implicit_unit)?,
        )
    } else {
        let radius = quantity(text, unit, implicit_unit)?;
        if radius < 0.0 {
            return None;
        }
        (-radius, radius)
    };
    (lower <= 0.0 && upper >= 0.0).then_some(Tolerance {
        lower,
        upper,
        unit: unit.into(),
    })
}

fn comparison(text: &str, unit: &str) -> Option<Comparison> {
    let (operator, number) = [
        ("<=", Operator::Le),
        (">=", Operator::Ge),
        ("<", Operator::Lt),
        (">", Operator::Gt),
    ]
    .iter()
    .find_map(|(prefix, operator)| text.strip_prefix(prefix).map(|number| (*operator, number)))?;
    Some(Comparison {
        operator,
        threshold: Quantity {
            value: quantity(number, unit, false)?,
            unit: unit.into(),
        },
    })
}

fn current_provenance(plan: &StructuredPlan, provenance: &Provenance) -> bool {
    (!provenance.location.trim().is_empty() || !provenance.excerpt.trim().is_empty())
        && plan.sources.iter().any(|source| {
            source.id == provenance.source_id
                && source.revision == provenance.revision
                && !source.revision.trim().is_empty()
        })
}

pub(super) fn reviewed_requirement_provenance(
    plan: &StructuredPlan,
    provenance: &[Provenance],
) -> bool {
    provenance
        .iter()
        .any(|evidence| evidence.source_id == plan.controlling_source)
        && provenance.iter().all(|evidence| {
            current_provenance(plan, evidence)
                && plan.sources.iter().any(|source| {
                    source.id == evidence.source_id
                        && source.revision == evidence.revision
                        && source.approved
                        && source.kind != SourceKind::Example
                })
        })
}

pub(super) fn resolve_conflicts(
    plan: &StructuredPlan,
    blockers: &mut Vec<String>,
) -> (Vec<ConflictResult>, BTreeMap<String, TxTest>) {
    let mut decisions = BTreeMap::new();
    let mut inconsistent = HashSet::new();
    let results: Vec<_> = plan
        .conflicts
        .iter()
        .map(|conflict| {
            let original = plan
                .requirements
                .iter()
                .find(|requirement| requirement.id == conflict.requirement_id);
            let mut revisions: BTreeMap<_, _> = conflict
                .statements
                .iter()
                .map(|statement| {
                    (
                        statement.provenance.source_id.clone(),
                        statement.provenance.revision.clone(),
                    )
                })
                .collect();
            if let Some(source) = plan
                .sources
                .iter()
                .find(|source| source.id == plan.controlling_source)
            {
                revisions.insert(source.id.clone(), source.revision.clone());
            }
            let current = conflict
                .statements
                .iter()
                .all(|statement| current_provenance(plan, &statement.provenance));
            let applicable: Vec<_> = plan
                .exceptions
                .iter()
                .filter(|exception| {
                    current
                        && exception.conflict_id == conflict.id
                        && exception.requirement_id == conflict.requirement_id
                        && exception.station == plan.station
                        && exception.source_revisions == revisions
                        && !exception.rationale.trim().is_empty()
                        && !exception.approver.trim().is_empty()
                        && !exception.approval_evidence.trim().is_empty()
                        && original.is_some_and(|requirement| {
                            compatible_decision(&requirement.test, &exception.decision, conflict)
                        })
                })
                .collect();
            let resolved_by = if applicable.len() == 1 {
                let exception = applicable[0];
                if let Some(previous) =
                    decisions.insert(conflict.requirement_id.clone(), exception.decision.clone())
                    && previous != exception.decision
                {
                    inconsistent.insert(conflict.requirement_id.clone());
                }
                Some(exception.id.clone())
            } else {
                None
            };
            ConflictResult {
                conflict: conflict.clone(),
                resolved_by,
            }
        })
        .collect();
    let mut results = results;
    for result in &mut results {
        if inconsistent.contains(&result.conflict.requirement_id) {
            result.resolved_by = None;
            decisions.remove(&result.conflict.requirement_id);
        }
    }
    for exception in &plan.exceptions {
        if !results
            .iter()
            .any(|result| result.resolved_by.as_deref() == Some(&exception.id))
        {
            blockers.push(format!(
                "{}: exception is unrelated, stale, ambiguous, or lacks approval evidence.",
                exception.id
            ));
        }
    }
    (results, decisions)
}

fn is_bluetooth_setup(test: &TxTest) -> bool {
    test.technology.as_deref() == Some("bluetooth")
        && test.purpose.as_deref() == Some("setup")
        && test.procedure.as_ref().is_some_and(|procedure| {
            procedure.device.split('#').next() == Some("DLLIOT")
                && procedure.function == "DUT_INSERT"
                && procedure
                    .parameters
                    .split('&')
                    .any(|assignment| assignment == "TECH=BT")
        })
}

fn compatible_decision(original: &TxTest, decision: &TxTest, conflict: &SourceConflict) -> bool {
    let mut dimensions = original.clone();
    if original.technology.as_deref() == Some("bluetooth")
        && conflict.statements.iter().any(|statement| {
            statement.test.channel != original.channel
                || statement.test.frequency != original.frequency
        })
        && conflict.statements.iter().any(|statement| {
            statement.test.channel == decision.channel
                && statement.test.frequency == decision.frequency
                && (decision.channel.is_some() || decision.frequency.is_some())
        })
    {
        dimensions.channel = decision.channel;
        dimensions.frequency = decision.frequency.clone();
    }
    dimensions.power_target = decision.power_target.clone();
    dimensions.power_tolerance = decision.power_tolerance.clone();
    dimensions.frequency_offset = decision.frequency_offset.clone();
    dimensions.evm = decision.evm.clone();
    dimensions.packet_count = decision.packet_count;
    dimensions.input_level = decision.input_level.clone();
    dimensions.per = decision.per.clone();
    dimensions.rssi_tolerance = decision.rssi_tolerance.clone();
    dimensions == *decision
        && (original.power_target.is_none() || decision.power_target.is_some())
        && (original.power_tolerance.is_none() || decision.power_tolerance.is_some())
        && (original.frequency_offset.is_none() || decision.frequency_offset.is_some())
        && (original.evm.is_none() || decision.evm.is_some())
        && (original.packet_count.is_none() || decision.packet_count.is_some())
        && (original.input_level.is_none() || decision.input_level.is_some())
        && (original.per.is_none() || decision.per.is_some())
        && (original.rssi_tolerance.is_none() || decision.rssi_tolerance.is_some())
}

fn bounded_test(test: &TxTest) -> bool {
    !matches!(&test.chains, Some(Chains::PerChain(masks)) if masks.len() > 16)
        && test.procedure.as_ref().is_none_or(|procedure| {
            procedure.device.len() <= 256
                && procedure.function.len() <= 256
                && procedure.parameters.len() <= 8192
                && procedure.criteria.len() <= 8192
        })
        && [
            test.technology.as_deref(),
            test.purpose.as_deref(),
            test.band.as_deref(),
            test.standard.as_deref(),
            test.rate.as_deref(),
            test.frequency
                .as_ref()
                .map(|quantity| quantity.unit.as_str()),
            test.bandwidth
                .as_ref()
                .map(|quantity| quantity.unit.as_str()),
            test.power_target
                .as_ref()
                .map(|quantity| quantity.unit.as_str()),
            test.power_tolerance
                .as_ref()
                .map(|tolerance| tolerance.unit.as_str()),
            test.frequency_offset
                .as_ref()
                .map(|tolerance| tolerance.unit.as_str()),
            test.evm
                .as_ref()
                .map(|comparison| comparison.threshold.unit.as_str()),
            test.input_level
                .as_ref()
                .map(|quantity| quantity.unit.as_str()),
            test.per
                .as_ref()
                .map(|comparison| comparison.threshold.unit.as_str()),
            test.rssi_tolerance
                .as_ref()
                .map(|tolerance| tolerance.unit.as_str()),
            test.calibration_interval
                .as_ref()
                .map(|quantity| quantity.unit.as_str()),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.len() <= 256)
}
