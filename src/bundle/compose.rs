use std::collections::{BTreeMap, HashSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Engine, Result, grammar, model::Severity};

use super::plan::{self, Applicability, Chains, ComparePlanRequest, FlowVariant, Operator, TxTest};
use super::{BundleDialect, BundleFile, MAX_TEXT_BYTES, invalid_request};

const BASE_FILES: [&str; 6] = [
    "MAIN_FLOW.ini",
    "MACRO_LIST.ini",
    "FACTORY_SETTING.ini",
    "PARAMETER_LIST.ini",
    "RD_SETTING.ini",
    "TEST_SPEC.ini",
];
const SYNTHETIC_MARKER: &str = "; SYNTHETIC FIXTURE ONLY";
const MAX_OUTPUT_BYTES: usize = 16 * MAX_TEXT_BYTES;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComposeBundleRequest {
    pub comparison: ComparePlanRequest,
    pub review: Option<Review>,
    pub draft_approval: Option<Approval>,
    pub template_pack: Option<TemplatePack>,
    #[serde(default)]
    pub procedure_templates: Vec<ProcedureTemplate>,
    pub flow_anchor: String,
    #[serde(default)]
    pub station_settings: Vec<StationReference>,
    #[serde(default)]
    pub report_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub plan: Approval,
    pub base: Approval,
    pub settings: Approval,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub subject_identity: String,
    pub approver: String,
    pub evidence: String,
    pub kind: ApprovalKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    SyntheticFixture,
    OperatorReview,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplatePack {
    pub id: String,
    pub version: String,
    pub source: BundleFile,
    pub corrected: BundleFile,
    pub corrections: Vec<Correction>,
    #[serde(default)]
    pub unresolved_questions: Vec<String>,
    pub approval: Option<Approval>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcedureTemplate {
    pub requirement_id: String,
    pub template_pack: TemplatePack,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub before: String,
    pub after: String,
    pub evidence: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StationReference {
    pub role: SettingRole,
    pub file: String,
    pub section: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingRole {
    Equipment,
    Routing,
    Timing,
    SupportFile,
    Credential,
}

impl ComposeBundleRequest {
    pub fn check_bounds(&self) -> Result<()> {
        self.comparison.check_bounds()?;
        if serde_json::to_vec(self)
            .map_err(|_| invalid_request("composition cannot be represented"))?
            .len()
            > MAX_TEXT_BYTES
            || self.station_settings.len() > 64
            || self.report_metadata.len() > 32
            || self.flow_anchor.len() > 512
            || self.procedure_templates.len() > 128
            || self
                .procedure_templates
                .iter()
                .any(|item| !pack_bounds(&item.template_pack))
            || self.template_pack.as_ref().is_some_and(|pack| {
                pack.corrections.len() > 64
                    || pack.unresolved_questions.len() > 128
                    || pack.source.text.len() > 8192
                    || pack.corrected.text.len() > 8192
            })
        {
            return Err(invalid_request(
                "composition exceeds 1048576 serialized bytes, 64 settings/corrections, 128 template questions, 8192 template bytes or 512 anchor bytes",
            ));
        }
        Ok(())
    }
}

pub fn compose(mut request: ComposeBundleRequest, engine: &Engine) -> Result<Value> {
    request.check_bounds()?;
    let original = request.comparison.bundle.files.clone();
    let mut catalog = serde_json::to_value(&engine.snapshot)
        .map_err(|_| invalid_request("catalog identity cannot be represented"))?;
    if let Value::Object(tables) = &mut catalog {
        for table in tables.values_mut() {
            if let Value::Array(rows) = table {
                rows.sort_by_key(Value::to_string);
            }
        }
    }
    let template_identity = request
        .template_pack
        .as_ref()
        .map(|pack| {
            identity(&json!({
                "id":pack.id,"version":pack.version,"source":pack.source,
                "corrected":pack.corrected,"corrections":pack.corrections,
                "unresolved_questions":pack.unresolved_questions
            }))
        })
        .transpose()?;
    let identities = json!({
        "plan":identity(&request.comparison.plan)?,
        "base":identity(&request.comparison.bundle)?,
        "settings":identity(&json!({"base":request.comparison.bundle,"references":request.station_settings}))?,
        "template_pack":template_identity,
        "procedures":request.procedure_templates.iter().map(|item| {
            Ok((item.requirement_id.clone(), pack_identity(&item.template_pack)?))
        }).collect::<Result<BTreeMap<_, _>>>()?,
        "catalog":identity(&catalog)?,
        "flow":identity(&json!({"selected_flow":request.comparison.bundle.selected_flow,
            "variant":request.comparison.flow_variant,"anchor":request.flow_anchor}))?
    });
    let mut blockers = Vec::new();
    let approvals = request
        .review
        .as_ref()
        .map(|review| [&review.plan, &review.base, &review.settings]);
    let synthetic = approvals.is_some_and(|items| {
        items
            .iter()
            .any(|item| item.kind == ApprovalKind::SyntheticFixture)
    }) || request
        .template_pack
        .as_ref()
        .and_then(|pack| pack.approval.as_ref())
        .is_some_and(|approval| approval.kind == ApprovalKind::SyntheticFixture)
        || request.procedure_templates.iter().any(|item| {
            item.template_pack
                .approval
                .as_ref()
                .is_some_and(|approval| approval.kind == ApprovalKind::SyntheticFixture)
        });
    let mut allowed = true;
    for name in BASE_FILES {
        if !original
            .iter()
            .any(|file| file.name.eq_ignore_ascii_case(name))
        {
            blockers.push(format!(
                "Missing six-file base member {name}; supply its approved contents."
            ));
            allowed = false;
        }
    }
    if synthetic
        && !original
            .iter()
            .all(|file| file.text.lines().next() == Some(SYNTHETIC_MARKER))
    {
        blockers.push(
            "Synthetic approval evidence cannot authorize unmarked station artifacts.".into(),
        );
        allowed = false;
    }
    if let Some(approvals) = approvals {
        for (name, approval) in ["plan", "base", "settings"].into_iter().zip(approvals) {
            if !approved(approval, identities[name].as_str().unwrap_or("")) {
                blockers.push(format!(
                    "Current reviewed {name} identity, approver and approval evidence are required."
                ));
                allowed = false;
            }
        }
    } else {
        blockers
            .push("Reviewed plan, base and station settings approval evidence is required.".into());
        allowed = false;
    }
    for role in [
        SettingRole::Equipment,
        SettingRole::Routing,
        SettingRole::Timing,
        SettingRole::SupportFile,
        SettingRole::Credential,
    ] {
        if !request
            .station_settings
            .iter()
            .any(|setting| setting.role == role && setting_value(&original, setting).is_some())
        {
            blockers.push(format!("Supply an approved nonempty {role:?} setting reference; no operational value will be invented."));
            allowed = false;
        }
    }
    if request
        .station_settings
        .iter()
        .any(|setting| setting_value(&original, setting).is_none())
    {
        blockers.push("Station setting references must resolve uniquely in their supplied file, section and key.".into());
        allowed = false;
    }
    let pack = request.template_pack.as_ref();
    if !pack.is_some_and(|pack| {
        pack.approval
            .as_ref()
            .is_some_and(|approval| approved(approval, template_identity.as_deref().unwrap_or("")))
            && corrected_copy(pack)
            && template_shape(&pack.corrected.text)
    }) {
        blockers.push("Supply a versioned reviewed TX template with separate sanitized source/corrected copies, evidenced corrections, current approval and audited placeholders.".into());
        allowed = false;
    }
    if let Some(pack) = pack {
        blockers.extend(pack.unresolved_questions.iter().cloned());
        if !pack.unresolved_questions.is_empty() {
            allowed = false;
        }
        let timeout = pack
            .corrected
            .text
            .lines()
            .nth(1)
            .and_then(|row| row.split('|').nth(4));
        if !request
            .station_settings
            .iter()
            .filter(|setting| setting.role == SettingRole::Timing)
            .any(|setting| {
                setting_value(&original, setting).is_some_and(|value| {
                    timeout == Some(format!("*V:{}-{}#", setting.section, setting.key).as_str())
                        || (timeout == Some(value)
                            && value.parse::<u64>().is_ok_and(|value| value > 0))
                })
            })
        {
            blockers.push("Template timing must reuse a supplied approved timing reference or its exact positive numeric value.".into());
            allowed = false;
        }
    }
    if request.comparison.bundle.dialect != BundleDialect::Hh5k {
        blockers.push("This composer supports explicit hh5k flow only.".into());
        allowed = false;
    }
    if !request.comparison.plan.sources.iter().any(|source| {
        source.id == request.comparison.plan.controlling_source
            && source.approved
            && source.kind != plan::SourceKind::Example
            && !source.revision.trim().is_empty()
    }) || request.comparison.plan.station != "HH5K Wireless Test_2"
    {
        blockers.push("Reviewed controlling requirements and HH5K Wireless Test_2 station identity are required.".into());
        allowed = false;
    }
    let (conflicts, decisions) = plan::resolve_conflicts(&request.comparison.plan, &mut blockers);
    let mut links = Vec::new();
    let mut inserted = 0;
    let mut procedure_ids = HashSet::new();
    if request.procedure_templates.iter().any(|item| {
        !procedure_ids.insert(item.requirement_id.as_str())
            || !request
                .comparison
                .plan
                .requirements
                .iter()
                .any(|requirement| requirement.id == item.requirement_id)
    }) {
        blockers.push("Procedure templates require unique, existing requirement IDs.".into());
        allowed = false;
    }
    let order = requirement_order(
        &request.comparison.plan.requirements,
        request.comparison.flow_variant,
    );
    if order.is_none() {
        blockers.push(
            "Procedure dependencies must identify existing requirements applicable to the selected variant without cycles."
                .into(),
        );
        allowed = false;
    }
    if allowed && let Some(pack) = pack {
        for index in order.unwrap_or_default() {
            let requirement = &request.comparison.plan.requirements[index];
            if conflicts.iter().any(|conflict| {
                conflict.conflict.requirement_id == requirement.id && conflict.resolved_by.is_none()
            }) || !requirement.unresolved_questions.is_empty()
                || !plan::reviewed_requirement_provenance(
                    &request.comparison.plan,
                    &requirement.provenance,
                )
            {
                blockers.push(format!("{}: resolve source conflicts/questions and review current controlling provenance before generation.", requirement.id));
                continue;
            }
            let test = decisions.get(&requirement.id).unwrap_or(&requirement.test);
            let bluetooth = test.technology.as_deref() == Some("bluetooth");
            let wifi_tx = !bluetooth && test.purpose.as_deref() == Some("tx");
            let section = format!(
                "{}_{index}",
                if bluetooth {
                    "BT_DRAFT"
                } else if wifi_tx {
                    "TX_DRAFT"
                } else {
                    "WIFI_DRAFT"
                }
            );
            let Some((device, function, parameters, criteria, definitions)) =
                encode_procedure(test, &section)
            else {
                blockers.push(format!("{}: only fully specified 6 GHz Wi-Fi TX/RX/calibration, Bluetooth TX/RX and explicit setup/save/cleanup encodings are supported; missing/unaudited dimensions remain incomplete.", requirement.id));
                continue;
            };
            let template = if wifi_tx {
                Some(pack)
            } else {
                request
                    .procedure_templates
                    .iter()
                    .find(|item| item.requirement_id == requirement.id)
                    .map(|item| &item.template_pack)
            };
            let Some(template) = template.filter(|template| {
                let expected = identities["procedures"][&requirement.id]
                    .as_str()
                    .unwrap_or("");
                (wifi_tx
                    || template
                        .approval
                        .as_ref()
                        .is_some_and(|approval| approved(approval, expected)))
                    && corrected_copy(template)
                    && template.unresolved_questions.is_empty()
                    && procedure_shape(&template.corrected.text, &device, &function, !wifi_tx)
                    && supplied_macro(&template.corrected.text, &original)
                    && approved_timing(template, &original, &request.station_settings)
            }) else {
                blockers.push(format!("{}: supply a current approved RX/calibration/procedure template with evidenced corrections, audited placeholders and approved timing; unresolved template questions remain blockers.", requirement.id));
                continue;
            };
            let mut checked_parameters = parameters.clone();
            let mut checked_criteria = criteria.clone();
            for line in definitions.lines().skip(1) {
                if let Some((key, value)) = line.split_once('=') {
                    let reference = format!("*V:{section}-{key}#");
                    checked_parameters = checked_parameters.replace(&reference, value);
                    checked_criteria = checked_criteria.replace(&reference, value);
                }
            }
            if !supported(
                engine,
                request.comparison.bundle.device_scope.as_deref(),
                &device,
                &function,
                &checked_parameters,
                &checked_criteria,
            ) {
                blockers.push(format!("{}: scoped procedure catalog knowledge/encoding is missing or unsupported; no defaults inserted.", requirement.id));
                continue;
            }
            let mut candidate = request.comparison.bundle.clone();
            let procedure = template
                .corrected
                .text
                .replace("{{section}}", &section)
                .replace("{{parameters}}", &parameters)
                .replace("{{criteria}}", &criteria);
            if !insert(
                &mut candidate.files,
                &candidate.selected_flow,
                &request.flow_anchor,
                inserted,
                &section,
                &procedure,
                &definitions,
            ) || (ComparePlanRequest {
                bundle: candidate.clone(),
                plan: request.comparison.plan.clone(),
                flow_variant: request.comparison.flow_variant,
            })
            .check_bounds()
            .is_err()
            {
                blockers.push(format!("{}: composition needs a unique selected-flow comment anchor, collision-free section and available output/source-record budget.", requirement.id));
                continue;
            }
            request.comparison.bundle = candidate;
            inserted += 1;
            for key in definitions
                .lines()
                .skip(1)
                .filter_map(|line| line.split_once('=').map(|(key, _)| key))
            {
                links.push(json!({"requirement_id":requirement.id,"definition":{"file":"TEST_SPEC.ini","section":section,"key":key},
                    "usage":{"file":"MAIN_FLOW.ini","section":section,"row":"MEASURE","field":if matches!(key, "TARGET" | "INPUT") {"parameters"} else {"criteria"}},
                    "reference":format!("*V:{section}-{key}#")}));
            }
        }
    }
    let files = request.comparison.bundle.files.clone();
    let draft_identity = identity(&json!({"inputs":identities,"review":request.review,
        "template_approval":request.template_pack.as_ref().and_then(|pack| pack.approval.as_ref()),
        "procedure_approvals":request.procedure_templates,"files":files}))?;
    let declared_secrets: Vec<_> = request
        .station_settings
        .iter()
        .filter(|setting| setting.role == SettingRole::Credential)
        .filter_map(|setting| setting_value(&original, setting).map(str::to_string))
        .collect();
    let (mut comparison, mut secrets) =
        plan::compare_with_secrets(request.comparison, engine, &declared_secrets)?;
    let sampling_policy = comparison["sampling_policy"].clone();
    secrets.extend(super::diagnostic_secrets(&super::ValidateBundleRequest {
        files: original.clone(),
        selected_flow: "[TEST FLOW:Normal]".into(),
        dialect: BundleDialect::Hh5k,
        device_scope: None,
        runtime_bindings: Vec::new(),
        sensitive_values: Vec::new(),
    })?);
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets.dedup();
    if let Some(items) = comparison["blockers"].as_array() {
        blockers.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if synthetic {
        blockers.push("Synthetic fixture evidence is not approval of real station artifacts; operational review remains required.".into());
    }
    let diffs: Vec<_> = original
        .iter()
        .zip(&files)
        .filter(|(before, after)| before.text != after.text)
        .map(|(before, after)| {
            json!({"file":after.name,"format":"whole_file_unified",
            "text":full_diff(before, after)})
        })
        .collect();
    let footers: Vec<_> = original.iter().zip(&files).flat_map(|(before, after)| {
        before.text.lines().enumerate().filter(|(_, line)| {
            let text = line.to_ascii_lowercase();
            ["checksum", "crc", "revision", "footer"].iter().any(|word| text.contains(word))
        }).map(move |(line, text)| json!({"file":before.name,"line":line+1,"text":text,
            "verification":if before.text != after.text {"unverified_for_changed_content"} else {"historical_unverified"}}))
    }).collect();
    let validation = comparison["validation"].take();
    let template_approval_identity = request
        .template_pack
        .as_ref()
        .and_then(|pack| pack.approval.as_ref())
        .filter(|approval| approved(approval, identities["template_pack"].as_str().unwrap_or("")))
        .map(|approval| approval.subject_identity.clone());
    let status = if comparison["status"] == "invalid" {
        "invalid"
    } else if blockers.is_empty() && comparison["ready_for_review"] == true {
        "valid"
    } else {
        "incomplete"
    };
    let mut report = json!({
        "status":status,"ready_for_review":status == "valid",
        "draft_identity":draft_identity,"input_identities":identities,
        "artifact_authority":if synthetic {"synthetic_only"} else {"caller_supplied_review_evidence_not_authenticated"},
        "template_provenance":request.template_pack,
        "procedure_provenance":request.procedure_templates,
        "sampling_policy":sampling_policy,
        "diffs":diffs,"limit_links":links,"historical_footers":footers,
        "blockers":blockers,"comparison":comparison,
        "runtime_verification":"unchecked",
        "hardware_verification":"unchecked",
        "packaging":"unchecked","checksum":"not_refreshed",
        "export":"not_performed"
    });
    check_output_bounds(&report)?;
    plan::redact_summary(&mut report, &secrets);
    report["draft_approval"] = draft_approval_report(
        request.draft_approval.as_ref(),
        &draft_identity,
        status == "valid",
        &secrets,
    );
    report["draft_files"] =
        serde_json::to_value(files).map_err(|_| invalid_request("draft cannot be represented"))?;
    report["comparison"]["validation"] = validation;
    if let Some(identity) = template_approval_identity {
        report["template_provenance"]["approval"]["subject_identity"] = identity.into();
    }
    for (index, item) in request.procedure_templates.iter().enumerate() {
        if let Some(approval) = &item.template_pack.approval
            && approved(
                approval,
                identities["procedures"][&item.requirement_id]
                    .as_str()
                    .unwrap_or(""),
            )
        {
            report["procedure_provenance"][index]["template_pack"]["approval"]["subject_identity"] =
                approval.subject_identity.clone().into();
        }
    }
    check_output_bounds(&report)?;
    Ok(report)
}

fn draft_approval_report(
    approval: Option<&Approval>,
    draft_identity: &str,
    ready_for_review: bool,
    secrets: &[String],
) -> Value {
    let status = match approval {
        None => "not_supplied",
        Some(approval) if approval.subject_identity != draft_identity => "stale",
        Some(approval) if !approved(approval, draft_identity) => "incomplete_evidence",
        Some(approval) if !ready_for_review || approval.kind != ApprovalKind::OperatorReview => {
            "blocked"
        }
        Some(_) => "recorded_claim",
    };
    json!({
        "status":status,
        "authority":"client_verification_required",
        "claim":approval.map(|approval| json!({
            "subject_identity":if approval.subject_identity == draft_identity {
                approval.subject_identity.clone()
            } else {
                super::redact(&approval.subject_identity, secrets)
            },
            "approver":super::redact(&approval.approver, secrets),
            "evidence":super::redact(&approval.evidence, secrets),
            "kind":approval.kind
        }))
    })
}

fn check_output_bounds(report: &Value) -> Result<()> {
    if serde_json::to_vec(report)
        .map_err(|_| invalid_request("report cannot be represented"))?
        .len()
        > MAX_OUTPUT_BYTES
    {
        return Err(invalid_request(
            "composition report exceeds 16777216 bytes; reduce the supplied bundle/requirements; no output was exported",
        ));
    }
    Ok(())
}

fn identity(value: &impl Serialize) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| invalid_request("identity cannot be represented"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn pack_bounds(pack: &TemplatePack) -> bool {
    pack.corrections.len() <= 64
        && pack.unresolved_questions.len() <= 128
        && pack.source.text.len() <= 8192
        && pack.corrected.text.len() <= 8192
}

fn pack_identity(pack: &TemplatePack) -> Result<String> {
    identity(
        &json!({"id":pack.id,"version":pack.version,"source":pack.source,
        "corrected":pack.corrected,"corrections":pack.corrections,"unresolved_questions":pack.unresolved_questions}),
    )
}

fn requirement_order(
    requirements: &[plan::Requirement],
    variant: FlowVariant,
) -> Option<Vec<usize>> {
    let mut order = Vec::new();
    let mut remaining: Vec<_> = requirements
        .iter()
        .enumerate()
        .filter(|(_, requirement)| {
            requirement.applicability == Applicability::Mandatory
                || variant == FlowVariant::Sampling
        })
        .map(|(index, _)| index)
        .collect();
    while !remaining.is_empty() {
        let position = remaining.iter().position(|index| {
            requirements[*index].depends_on.iter().all(|id| {
                order
                    .iter()
                    .any(|done: &usize| requirements[*done].id == *id)
            })
        })?;
        order.push(remaining.remove(position));
    }
    Some(order)
}

fn approved_timing(
    pack: &TemplatePack,
    files: &[BundleFile],
    settings: &[StationReference],
) -> bool {
    let timeout = pack
        .corrected
        .text
        .lines()
        .nth(1)
        .and_then(|row| row.split('|').nth(4));
    settings
        .iter()
        .filter(|setting| setting.role == SettingRole::Timing)
        .any(|setting| {
            setting_value(files, setting).is_some_and(|value| {
                timeout == Some(format!("*V:{}-{}#", setting.section, setting.key).as_str())
                    || (timeout == Some(value) && value.parse::<u64>().is_ok_and(|value| value > 0))
            })
        })
}

fn approved(approval: &Approval, identity: &str) -> bool {
    approval.subject_identity == identity
        && !approval.approver.trim().is_empty()
        && !approval.evidence.trim().is_empty()
}

fn corrected_copy(pack: &TemplatePack) -> bool {
    if pack.id.trim().is_empty()
        || pack.version.trim().is_empty()
        || pack.source.name.eq_ignore_ascii_case(&pack.corrected.name)
        || pack.source.name.trim().is_empty()
        || pack.corrected.name.trim().is_empty()
    {
        return false;
    }
    let mut copy = pack.source.text.clone();
    for correction in &pack.corrections {
        if correction.before.is_empty()
            || correction.evidence.trim().is_empty()
            || copy.matches(&correction.before).count() != 1
        {
            return false;
        }
        let Some(unterminated) = correction.before.strip_suffix('\n') else {
            return false;
        };
        if correction.after != format!("{unterminated}\"\n") {
            return false;
        }
        copy = copy.replacen(&correction.before, &correction.after, 1);
        if copy.len() > 8192 {
            return false;
        }
    }
    copy == pack.corrected.text
}

fn template_shape(text: &str) -> bool {
    procedure_shape(text, "DLLWIFI_TEST", "TX_MULTI_VERIFICATION", false)
}

fn procedure_shape(text: &str, device: &str, function: &str, allow_macro: bool) -> bool {
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 || lines[0] != "[{{section}}]" {
        return false;
    }
    let Some(row) = lines[1]
        .strip_prefix("MEASURE=\"")
        .and_then(|row| row.strip_suffix('"'))
    else {
        return false;
    };
    let fields: Vec<_> = row.split('|').collect();
    fields.len() == 8
        && ((fields[0] == device && fields[1] == function)
            || allow_macro
                && fields[0] == "MACRO"
                && !fields[1].is_empty()
                && fields[1]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
        && fields[2] == "{{parameters}}"
        && fields[3] == "{{criteria}}"
        && !fields[4].is_empty()
        && !fields[4].contains(['"', '{', '}'])
        && fields[5..] == ["NEXT", "FAIL", ""]
}

fn supplied_macro(text: &str, files: &[BundleFile]) -> bool {
    let fields: Vec<_> = text.lines().nth(1).unwrap_or("").split('|').collect();
    if fields.first() != Some(&"MEASURE=\"MACRO") {
        return true;
    }
    let Some(name) = fields.get(1) else {
        return false;
    };
    files
        .iter()
        .flat_map(|file| file.text.lines())
        .filter(|line| line.trim().eq_ignore_ascii_case(&format!("[{name}]")))
        .count()
        == 1
}

fn setting_value<'a>(files: &'a [BundleFile], setting: &StationReference) -> Option<&'a str> {
    let file = files
        .iter()
        .find(|file| file.name.eq_ignore_ascii_case(&setting.file))?;
    let mut current = "";
    let mut values = Vec::new();
    let mut sections = 0;
    for line in file.text.lines().map(str::trim) {
        if line.starts_with([';', '#']) || line.is_empty() {
            continue;
        }
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current = section;
            if current.eq_ignore_ascii_case(&setting.section) {
                sections += 1;
            }
        } else if current.eq_ignore_ascii_case(&setting.section)
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case(&setting.key)
        {
            values.push(value.trim().trim_matches('"'));
        }
    }
    (sections == 1 && values.len() == 1 && !values[0].is_empty() && values[0] != "NULL")
        .then(|| values[0])
}

fn encode_tx(test: &TxTest, section: &str) -> Option<(String, String, String)> {
    if test.technology.as_deref()? != "wifi"
        || test.purpose.as_deref()? != "tx"
        || test.band.as_deref()? != "6G"
        || test.channel.is_some()
        || test.input_level.is_some()
        || test.per.is_some()
        || test.rssi_tolerance.is_some()
        || test.procedure.is_some()
        || test.calibration_interval.is_some()
        || test.frequency_offset.is_some()
    {
        return None;
    }
    let frequency = test.frequency.as_ref()?;
    let bandwidth = test.bandwidth.as_ref()?;
    let target = test.power_target.as_ref()?;
    let tolerance = test.power_tolerance.as_ref()?;
    let evm = test.evm.as_ref()?;
    let standard = test.standard.as_deref()?;
    let rate = test.rate.as_deref()?;
    if frequency.unit != "MHz"
        || bandwidth.unit != "MHz"
        || target.unit != "dBm"
        || tolerance.unit != "dB"
        || evm.threshold.unit != "dB"
        || evm.operator != Operator::Lt
        || frequency.value <= 0.0
        || bandwidth.value <= 0.0
        || tolerance.lower > tolerance.upper
        || [standard, rate].iter().any(|text| {
            text.is_empty()
                || !text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
    {
        return None;
    }
    let antennas = match test.chains.as_ref()? {
        Chains::PerChain(values)
            if !values.is_empty()
                && values.iter().all(|value| matches!(value, 1 | 2 | 4 | 8))
                && values.iter().collect::<HashSet<_>>().len() == values.len() =>
        {
            values
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
        _ => return None,
    };
    let count = test.packet_count?;
    if count == 0 {
        return None;
    }
    let parameters = format!(
        "BAND=6G&ANT={antennas}&STANDARD={standard}&FREQ={}&BW={}&DATA_RATE={rate}&TX_TARGET_POWER=*V:{section}-TARGET#&FRAME_COUNT={count}",
        frequency.value, bandwidth.value
    );
    let criteria = format!("POWER=*V:{section}-POWER#&EVM=*V:{section}-EVM#");
    let definitions = format!(
        "[{section}]\nTARGET={}dBm\nPOWER={}~{}dB\nEVM=<{}dB\n",
        target.value, tolerance.lower, tolerance.upper, evm.threshold.value
    );
    Some((parameters, criteria, definitions))
}

fn encode_procedure(
    test: &TxTest,
    section: &str,
) -> Option<(String, String, String, String, String)> {
    if let Some(procedure) = &test.procedure {
        let mut remaining = test.clone();
        remaining.procedure = None;
        remaining.purpose = None;
        if test.technology.as_deref() == Some("bluetooth") {
            remaining.technology = None;
        }
        if !matches!(test.purpose.as_deref(), Some("setup" | "save" | "cleanup"))
            || remaining != TxTest::default()
            || [
                &procedure.device,
                &procedure.function,
                &procedure.parameters,
                &procedure.criteria,
            ]
            .iter()
            .any(|value| {
                value.is_empty()
                    || value.contains(['|', '\r', '\n', '"', '{', '}'])
                    || super::semantics::has_reference(value)
            })
        {
            return None;
        }
        return Some((
            procedure.device.clone(),
            procedure.function.clone(),
            procedure.parameters.clone(),
            procedure.criteria.clone(),
            String::new(),
        ));
    }
    if test.technology.as_deref() == Some("bluetooth") {
        return encode_bluetooth(test, section);
    }
    if test.purpose.as_deref() == Some("tx") {
        let (parameters, criteria, definitions) = encode_tx(test, section)?;
        return Some((
            "DLLWIFI_TEST".into(),
            "TX_MULTI_VERIFICATION".into(),
            parameters,
            criteria,
            definitions,
        ));
    }
    if test.technology.as_deref()? != "wifi"
        || test.band.as_deref()? != "6G"
        || test.channel.is_some()
        || test.power_target.is_some()
        || test.power_tolerance.is_some()
        || test.evm.is_some()
        || test.frequency_offset.is_some()
        || test.procedure.is_some()
    {
        return None;
    }
    let standard = test.standard.as_deref()?;
    let antennas = match test.chains.as_ref()? {
        Chains::PerChain(values)
            if !values.is_empty()
                && values.iter().all(|value| matches!(value, 1 | 2 | 4 | 8))
                && values.iter().collect::<HashSet<_>>().len() == values.len() =>
        {
            values
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
        _ => return None,
    };
    let mut parameters = format!("BAND=6G&ANT={antennas}&STANDARD={standard}");
    if test.purpose.as_deref() == Some("calibration") {
        if !matches!(standard, "11AX" | "11BE")
            || test.input_level.is_some()
            || test.per.is_some()
            || test.rssi_tolerance.is_some()
            || test.packet_count.is_some()
            || test.rate.is_some()
        {
            return None;
        }
        if let Some(frequency) = &test.frequency {
            if frequency.unit != "MHz" || frequency.value <= 0.0 {
                return None;
            }
            parameters.push_str(&format!("&FREQ={}", frequency.value));
        }
        if let Some(bandwidth) = &test.bandwidth {
            if bandwidth.unit != "MHz" || bandwidth.value <= 0.0 {
                return None;
            }
            parameters.push_str(&format!("&BW={}", bandwidth.value));
        }
        return Some((
            "DLLWIFI_TEST".into(),
            "BRCM_RSSI_CALIBRATION".into(),
            parameters,
            "NULL".into(),
            String::new(),
        ));
    }
    let frequency = test.frequency.as_ref()?;
    let bandwidth = test.bandwidth.as_ref()?;
    let rate = test.rate.as_deref()?;
    let input = test.input_level.as_ref()?;
    let per = test.per.as_ref()?;
    let count = test.packet_count?;
    if test.purpose.as_deref() != Some("rx")
        || test.calibration_interval.is_some()
        || !matches!(
            (standard, bandwidth.value),
            ("11AX", 160.0) | ("11BE", 320.0)
        )
        || frequency.unit != "MHz"
        || frequency.value <= 0.0
        || bandwidth.unit != "MHz"
        || input.unit != "dBm"
        || per.threshold.unit != "%"
        || !(0.0..=100.0).contains(&per.threshold.value)
        || count == 0
        || rate.is_empty()
        || !rate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return None;
    }
    let operator = match per.operator {
        Operator::Lt => "<",
        Operator::Le => "<=",
        Operator::Eq => "=",
        Operator::Ge => ">=",
        Operator::Gt => ">",
    };
    parameters.push_str(&format!(
        "&FREQ={}&BW={}&DATA_RATE={rate}&RX_TARGET_POWER=*V:{section}-INPUT#&FRAME_COUNT={count}",
        frequency.value, bandwidth.value
    ));
    let mut criteria = format!("PER=*V:{section}-PER#");
    let mut definitions = format!(
        "[{section}]\nINPUT={}dBm\nPER={operator}{}%\n",
        input.value, per.threshold.value
    );
    if let Some(rssi) = &test.rssi_tolerance {
        if rssi.unit != "dB" || rssi.lower > rssi.upper {
            return None;
        }
        criteria.push_str(&format!("&RSSI=*V:{section}-RSSI#"));
        definitions.push_str(&format!("RSSI={}~{}dB\n", rssi.lower, rssi.upper));
    }
    Some((
        "DLLWIFI_TEST".into(),
        "RX_VERIFY_PER".into(),
        parameters,
        criteria,
        definitions,
    ))
}

fn encode_bluetooth(
    test: &TxTest,
    section: &str,
) -> Option<(String, String, String, String, String)> {
    if test.band.is_some()
        || test.standard.is_some()
        || test.channel.is_some()
        || test.bandwidth.is_some()
        || test.rate.is_some()
        || test.evm.is_some()
        || test.rssi_tolerance.is_some()
        || test.calibration_interval.is_some()
    {
        return None;
    }
    let frequency = test.frequency.as_ref()?;
    let Chains::Bitmask(antenna) = test.chains.as_ref()? else {
        return None;
    };
    if frequency.unit != "MHz" || frequency.value <= 0.0 || *antenna == 0 {
        return None;
    }
    let parameters = format!("ANT={antenna}&FREQ={}", frequency.value);
    let (function, parameters, criteria, definitions) = match test.purpose.as_deref()? {
        "tx" => {
            let target = test.power_target.as_ref()?;
            let power = test.power_tolerance.as_ref()?;
            let offset = test.frequency_offset.as_ref()?;
            if target.unit != "dBm"
                || power.unit != "dB"
                || offset.unit != "kHz"
                || power.lower > power.upper
                || offset.lower > offset.upper
                || test.input_level.is_some()
                || test.per.is_some()
                || test.packet_count.is_some()
            {
                return None;
            }
            (
                "TX_MULTI_VERIFY",
                format!("{parameters}&TX_TARGET_POWER=*V:{section}-TARGET#"),
                format!("POWER=*V:{section}-POWER#&FREQ_ERROR_KHZ=*V:{section}-OFFSET#"),
                format!(
                    "[{section}]\nTARGET={}\nPOWER={}~{}\nOFFSET={}~{}\n",
                    target.value, power.lower, power.upper, offset.lower, offset.upper
                ),
            )
        }
        "rx" => {
            let input = test.input_level.as_ref()?;
            let per = test.per.as_ref()?;
            let count = test.packet_count?;
            if input.unit != "dBm"
                || per.threshold.unit != "%"
                || per.operator != Operator::Lt
                || !(0.0..=100.0).contains(&per.threshold.value)
                || count == 0
                || test.power_target.is_some()
                || test.power_tolerance.is_some()
                || test.frequency_offset.is_some()
            {
                return None;
            }
            (
                "RX_VERIFY_PER",
                format!("{parameters}&RX_TARGET_POWER=*V:{section}-INPUT#&FRAME_COUNT={count}"),
                format!("PER=*V:{section}-PER#"),
                format!(
                    "[{section}]\nINPUT={}\nPER=<{}%\n",
                    input.value, per.threshold.value
                ),
            )
        }
        _ => return None,
    };
    Some((
        "DLLIOT".into(),
        function.into(),
        parameters,
        criteria,
        definitions,
    ))
}

fn supported(
    engine: &Engine,
    scope: Option<&str>,
    device: &str,
    function: &str,
    parameters: &str,
    criteria: &str,
) -> bool {
    let Ok(schema) = engine.get_function(device, function, scope) else {
        return false;
    };
    let Some(encoding) = grammar::bundle_profile(&schema.function) else {
        return false;
    };
    let mut issues = grammar::bundle_support_issues(&schema);
    for (raw, fields, criteria) in [
        (parameters, schema.parameters.as_slice(), false),
        (criteria, schema.criteria.as_slice(), true),
    ] {
        let raw = if raw == "NULL" { "" } else { raw };
        let values = grammar::parse_fields(raw, fields, encoding, criteria, &mut issues);
        grammar::emit_fields(fields, &values, encoding, criteria, &mut issues);
    }
    !issues
        .iter()
        .any(|issue| issue.severity != Severity::Warning || issue.code == "unknown_criteria_key")
}

fn insert(
    files: &mut [BundleFile],
    selected_flow: &str,
    anchor: &str,
    inserted: usize,
    section: &str,
    procedure: &str,
    definitions: &str,
) -> bool {
    if anchor.lines().count() != 1
        || !anchor.trim_start().starts_with(';')
        || !anchor.ends_with('\n')
    {
        return false;
    }
    if files.iter().any(|file| {
        file.text
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(&format!("[{section}]")))
    }) {
        return false;
    }
    let Some(main) = files
        .iter_mut()
        .find(|file| file.name.eq_ignore_ascii_case("MAIN_FLOW.ini"))
    else {
        return false;
    };
    if main.text.matches(anchor).count() != 1 {
        return false;
    }
    let Some(position) = main.text.find(anchor) else {
        return false;
    };
    if position > 0 && !main.text[..position].ends_with('\n') {
        return false;
    }
    let current = main.text[..position]
        .lines()
        .rev()
        .find(|line| line.trim().starts_with('['))
        .map(str::trim);
    if current != Some(selected_flow) {
        return false;
    }
    let newline = if main.text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let start = position + anchor.len();
    let offset = main.text[start..]
        .split_inclusive('\n')
        .take(inserted)
        .map(str::len)
        .sum::<usize>();
    main.text
        .insert_str(start + offset, &format!("{section}=\"{section}\"{newline}"));
    append_text(
        &mut main.text,
        &procedure.replace("\r\n", "\n").replace('\n', newline),
    );
    let Some(spec) = files
        .iter_mut()
        .find(|file| file.name.eq_ignore_ascii_case("TEST_SPEC.ini"))
    else {
        return false;
    };
    let newline = if spec.text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    append_text(&mut spec.text, &definitions.replace('\n', newline));
    true
}

fn append_text(text: &mut String, addition: &str) {
    if addition.is_empty() {
        return;
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(addition);
}

fn full_diff(before: &BundleFile, after: &BundleFile) -> String {
    let mut diff = format!(
        "--- a/{}\n+++ b/{}\n@@ -1,{} +1,{} @@\n",
        before.name,
        after.name,
        before.text.lines().count(),
        after.text.lines().count()
    );
    for (prefix, text) in [('-', &before.text), ('+', &after.text)] {
        for line in text.split_inclusive('\n') {
            diff.push(prefix);
            diff.push_str(line);
            if !line.ends_with('\n') {
                diff.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    diff
}
