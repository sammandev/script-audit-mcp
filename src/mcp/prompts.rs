//! Workflow prompts. Each prompt takes string arguments (as MCP prompt arguments are) and tells
//! the model which tools to call, in order. Tool names appear in backticks.

use rmcp::{
    ErrorData,
    model::{GetPromptResult, JsonObject, Prompt, PromptArgument, PromptMessage, Role},
};

struct Spec {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    /// `(name, description, required)`.
    arguments: &'static [(&'static str, &'static str, bool)],
    /// Allowed values for enumerated arguments.
    choices: &'static [(&'static str, &'static [&'static str])],
    render: fn(&Arguments) -> String,
}

const DEVICE: (&str, &str, bool) = (
    "device",
    "Script device token, such as SSH or DLLWIFI_TEST (an Interface name is accepted).",
    true,
);
const DEVICE_SCOPE: (&str, &str, bool) = (
    "device_scope",
    "Optional Device scope for scoped definitions; defaults to the resolved Interface.",
    false,
);
const LINE: (&str, &str, bool) = ("line", "The Script line, pipe-delimited.", true);
const SELECTED_FLOW: (&str, &str, bool) = (
    "selected_flow",
    "The TEST FLOW section to analyse, such as [TEST FLOW:Normal].",
    true,
);

const SPECS: [Spec; 6] = [
    Spec {
        name: "compose-test-step",
        title: "Compose a Test Step",
        description: "Find a ready Function on a Script device for a test goal, then compose and validate its Script line.",
        arguments: &[
            DEVICE,
            (
                "goal",
                "What the step must do or measure, in plain words.",
                true,
            ),
            DEVICE_SCOPE,
        ],
        choices: &[],
        render: compose_test_step,
    },
    Spec {
        name: "explain-script-line",
        title: "Explain a Script Line",
        description: "Split a Script line into its fields and explain each against the catalog definitions.",
        arguments: &[LINE, DEVICE_SCOPE],
        choices: &[],
        render: explain_script_line,
    },
    Spec {
        name: "review-ini-bundle",
        title: "Review an INI Bundle",
        description: "Validate supplied INI bundle files for one flow and explain every finding by layer.",
        arguments: &[
            SELECTED_FLOW,
            ("dialect", "Bundle dialect: hh5k or checker_legacy.", true),
            DEVICE_SCOPE,
        ],
        choices: &[("dialect", &["hh5k", "checker_legacy"])],
        render: review_ini_bundle,
    },
    Spec {
        name: "plan-to-bundle",
        title: "Test Plan to INI Bundle",
        description: "Compare approved test-plan requirements with a base bundle, then preview a reviewable draft.",
        arguments: &[
            SELECTED_FLOW,
            (
                "flow_variant",
                "Flow variant to build: normal or sampling.",
                true,
            ),
        ],
        choices: &[("flow_variant", &["normal", "sampling"])],
        render: plan_to_bundle,
    },
    Spec {
        name: "audit-function-readiness",
        title: "Audit Function Readiness",
        description: "Report which Functions on a Script device are not ready and which definitions or grammar block them.",
        arguments: &[
            DEVICE,
            ("function", "Optional single Function name to audit.", false),
        ],
        choices: &[],
        render: audit_function_readiness,
    },
    Spec {
        name: "troubleshoot-failing-line",
        title: "Troubleshoot a Failing Line",
        description: "Diagnose why a Script line is invalid or incomplete and propose a corrected, validated line.",
        arguments: &[
            LINE,
            ("symptom", "Optional observed error or behaviour.", false),
            DEVICE_SCOPE,
        ],
        choices: &[],
        render: troubleshoot_failing_line,
    },
];

pub(super) fn list() -> Vec<Prompt> {
    SPECS
        .iter()
        .map(|spec| {
            let arguments = spec
                .arguments
                .iter()
                .map(|(name, description, required)| {
                    PromptArgument::new(*name)
                        .with_description(*description)
                        .with_required(*required)
                })
                .collect();
            Prompt::new(spec.name, Some(spec.description), Some(arguments)).with_title(spec.title)
        })
        .collect()
}

pub(super) fn get(name: &str, arguments: Option<JsonObject>) -> Result<GetPromptResult, ErrorData> {
    let spec = SPECS
        .iter()
        .find(|spec| spec.name == name)
        .ok_or_else(|| ErrorData::invalid_params(format!("unknown prompt: {name}"), None))?;
    let arguments = Arguments::parse(spec, arguments.unwrap_or_default())?;
    Ok(GetPromptResult::new(vec![PromptMessage::new_text(
        Role::User,
        (spec.render)(&arguments),
    )])
    .with_description(spec.description))
}

struct Arguments(Vec<(&'static str, String)>);

impl Arguments {
    fn parse(spec: &Spec, supplied: JsonObject) -> Result<Self, ErrorData> {
        let invalid = |message: String| ErrorData::invalid_params(message, None);
        if let Some(unknown) = supplied
            .keys()
            .find(|key| !spec.arguments.iter().any(|(name, ..)| name == key))
        {
            return Err(invalid(format!(
                "{}: unknown argument {unknown}",
                spec.name
            )));
        }
        let mut values = Vec::new();
        for (name, _, required) in spec.arguments {
            let value = match supplied.get(*name) {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(value)) => {
                    Some(value.trim()).filter(|value| !value.is_empty())
                }
                Some(_) => return Err(invalid(format!("{}: {name} must be a string", spec.name))),
            };
            let Some(value) = value else {
                if *required {
                    return Err(invalid(format!("{}: {name} is required", spec.name)));
                }
                continue;
            };
            if let Some((_, allowed)) = spec.choices.iter().find(|(choice, _)| choice == name)
                && !allowed.contains(&value)
            {
                return Err(invalid(format!(
                    "{}: {name} must be one of {}",
                    spec.name,
                    allowed.join(", ")
                )));
            }
            values.push((*name, value.to_string()));
        }
        Ok(Self(values))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> &str {
        self.get(name).unwrap_or_default()
    }

    /// `, device_scope "X"` when a Device scope was supplied.
    fn scope_clause(&self) -> String {
        self.get("device_scope")
            .map(|scope| format!(" with `device_scope` \"{scope}\""))
            .unwrap_or_default()
    }
}

fn compose_test_step(arguments: &Arguments) -> String {
    let device = arguments.required("device");
    let goal = arguments.required("goal");
    let scope = arguments.scope_clause();
    format!(
        "Compose one Script line on Script device \"{device}\" that does this: {goal}

Use the Script Audit tools in this order and do not invent values:
1. Call `get_device` with `device` \"{device}\" to confirm the Script device and see its readiness counts. On \"unknown_device\", pick from the returned candidates.
2. Call `search_catalog` with a `query` built from the goal, or `list_functions` with `device` \"{device}\" and `composable_only` true, to choose a Function.
3. Call `get_function_readiness` for the chosen Function. Only a \"ready\" Function can be composed as a line; otherwise explain the blockers and stop.
4. Call `get_function`{scope} for its parameters, criteria, value patterns, and Examples. Call `suggest_criteria` and `list_examples` for typical values.
5. Ask the user for any required value you cannot source from the goal, the definitions, or an Example. Never apply a default automatically.
6. Call `compose_line` with `device`, `function`, `params`, `criteria`, and an explicit `timeout` in milliseconds{scope}.
7. Call `validate_line` on the result and report the line, its status, and any diagnostics.

The resource docs://script-grammar describes the line grammar."
    )
}

fn explain_script_line(arguments: &Arguments) -> String {
    let line = arguments.required("line");
    let scope = arguments.scope_clause();
    format!(
        "Explain this Script line field by field:

{line}

1. Call `parse_line` with `line` set to the line above{scope}. It returns each field and links parameters and criteria to their definitions.
2. Call `validate_line` with the same `line`{scope} for the status and diagnostics.
3. Call `get_function` for the Function's descriptions, value patterns, and Examples. Use `get_definition` for any field whose definition is missing or unclear.
4. Explain the Script device, the Function, each parameter and criterion (value, meaning, unit, and whether it is required), the timeout, and any pass, fail, or error-code fields. Note references such as *V:Section# that a single line cannot resolve.

Read docs://script-grammar and docs://script-devices for the rules."
    )
}

fn review_ini_bundle(arguments: &Arguments) -> String {
    let flow = arguments.required("selected_flow");
    let dialect = arguments.required("dialect");
    let scope = arguments.scope_clause();
    format!(
        "Review the INI bundle files the user supplied for flow {flow} in the {dialect} dialect.

1. Collect the files as name and text pairs; MAIN_FLOW.ini is required and MACRO_LIST.ini enables macro checks. Ask for any that are missing.
2. Call `validate_ini_bundle` with `files`, `selected_flow` \"{flow}\", and `dialect` \"{dialect}\"{scope}. Pass `runtime_bindings` only for values the user states, and list secrets in `sensitive_values`.
3. Group findings by layer (structure, control flow, references, catalog) and severity. For each catalog finding, call `parse_line` on the row and `get_function` for the Function it uses.
4. For a fixable row, propose a corrected line and confirm it with `validate_line`.
5. Summarize the overall status, the blockers, and what remains unchecked. Never claim runtime behaviour the report marks as unchecked.

Read docs://ini-bundle-dialects for the dialect rules."
    )
}

fn plan_to_bundle(arguments: &Arguments) -> String {
    let flow = arguments.required("selected_flow");
    let variant = arguments.required("flow_variant");
    format!(
        "Turn the approved test plan into a reviewable INI bundle draft for flow {flow}, variant {variant}.

1. Extract structured requirements from the plan the user supplied, keeping a source and revision for each. Do not invent limits, rates, or settings.
2. Call `compare_plan_to_bundle` with the base `bundle` (all six files, `selected_flow` \"{flow}\", `dialect` \"hh5k\"), the `plan`, and `flow_variant` \"{variant}\".
3. Report coverage, conflicts, and blockers. Ask the user to resolve each conflict, and stop if blockers remain.
4. Call `compose_ini_bundle` with that request as `comparison`, plus a `flow_anchor` and the `station_settings` the user approves. The result is a read-only draft and diff.
5. Call `validate_ini_bundle` on the drafted files and present the diff, validation status, and remaining approval gates. Nothing is exported without explicit user approval.

Read docs://ini-bundle-dialects for the bundle rules."
    )
}

fn audit_function_readiness(arguments: &Arguments) -> String {
    let device = arguments.required("device");
    let target = arguments.get("function").map_or_else(
        || "every Function on it".to_string(),
        |function| format!("Function {function}"),
    );
    format!(
        "Audit readiness for Script device \"{device}\", {target}.

1. Call `get_device` with `device` \"{device}\" for its readiness counts and linked fields.
2. Call `list_functions` with `device` \"{device}\" to list each Function's readiness, unless a single Function was named.
3. For each Function that is not \"ready\", call `get_function_readiness` and record its line issues, bundle issues, and unaudited script keys.
4. For a linked field with no definition, call `get_definition` and `find_functions_using` to see whether it is defined elsewhere or in another Device scope.
5. Report a table of Function, readiness, and blockers, grouped by cause (missing definition, unsupported grammar, unaudited keys). Suggest catalog fixes, and do not compose lines for Functions that are not ready."
    )
}

fn troubleshoot_failing_line(arguments: &Arguments) -> String {
    let line = arguments.required("line");
    let scope = arguments.scope_clause();
    let symptom = arguments
        .get("symptom")
        .map(|symptom| format!("\nObserved symptom: {symptom}\n"))
        .unwrap_or_default();
    format!(
        "Find out why this Script line fails and propose a fix:

{line}
{symptom}
1. Call `validate_line` with `line` set to the line above{scope}. Read each diagnostic's code, field, and message.
2. Call `parse_line` with the same `line` to see how each field was split and which definitions it matched.
3. On \"unknown_device\" or \"unknown_function\", use the returned candidates, `list_devices`, or `search_catalog` to find the intended target.
4. Call `get_function_readiness` and `get_function` to check grammar support, required fields, and value patterns. Use `suggest_criteria` for valid criteria.
5. Build the corrected line with `compose_line`, confirm it with `validate_line`, and explain each change. If the line is valid but the runtime still fails, say which parts the server cannot check, such as runtime references.

Read docs://script-grammar for the line rules."
    )
}
