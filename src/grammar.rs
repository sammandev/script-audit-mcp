use std::collections::BTreeMap;

use regex::Regex;

use crate::model::{
    ComposeRequest, ComposeResult, CriteriaInput, Definition, Diagnostic, Field, Function,
    FunctionSchema, Severity, Value,
};
use crate::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Raw,
    Named,
}

pub(crate) fn profile(function: &Function) -> Option<Encoding> {
    if function.source == "BUILT-IN"
        && function.interface == "SSH"
        && matches!(
            function.name.as_str(),
            "OPEN" | "CLOSE" | "SENDSTR" | "SENDSTR_AND_WAITSTR" | "WAITSTR"
        )
        && function.convention == Some(1)
    {
        Some(Encoding::Raw)
    } else if function.source == "DLL"
        && function.interface == "WIFI_TEST"
        && function.name == "TX_MULTI_VERIFICATION"
        && function.convention == Some(2)
    {
        Some(Encoding::Named)
    } else {
        None
    }
}

pub(crate) fn diagnostic(
    field: &str,
    code: &str,
    message: impl Into<String>,
    severity: Severity,
) -> Diagnostic {
    Diagnostic {
        field: field.into(),
        code: code.into(),
        message: message.into(),
        severity,
    }
}

pub(crate) fn bundle_profile(function: &Function) -> Option<Encoding> {
    profile(function).or_else(|| {
        (function.source == "DLL"
            && ((function.interface == "WIFI_TEST"
                && matches!(
                    function.name.as_str(),
                    "RX_VERIFY_PER" | "BRCM_RSSI_CALIBRATION"
                ))
                || (function.interface == "IOT"
                    && matches!(
                        function.name.as_str(),
                        "DUT_INSERT" | "TX_MULTI_VERIFY" | "RX_VERIFY_PER"
                    )))
            && function.convention == Some(2))
        .then_some(Encoding::Named)
    })
}

pub(crate) fn support_issues(schema: &FunctionSchema) -> Vec<Diagnostic> {
    support_issues_with_bundle_keys(schema, false)
}

pub(crate) fn bundle_support_issues(schema: &FunctionSchema) -> Vec<Diagnostic> {
    support_issues_with_bundle_keys(schema, true)
}

fn support_issues_with_bundle_keys(schema: &FunctionSchema, bundle: bool) -> Vec<Diagnostic> {
    let mut issues = Vec::new();
    let Some(encoding) = (if bundle {
        bundle_profile(&schema.function)
    } else {
        profile(&schema.function)
    }) else {
        return vec![diagnostic(
            "function",
            "unsupported_grammar",
            "no audited grammar profile for this function",
            Severity::Incomplete,
        )];
    };
    if encoding == Encoding::Raw && schema.parameters.len() != 1 {
        issues.push(diagnostic(
            "params",
            "unsupported_grammar",
            "audited SSH operations require one payload definition",
            Severity::Incomplete,
        ));
    }
    for (prefix, fields) in [
        ("params", &schema.parameters),
        ("criteria", &schema.criteria),
    ] {
        if encoding == Encoding::Raw && fields.len() > 1 {
            issues.push(diagnostic(
                prefix,
                "unsupported_grammar",
                "raw profile requires at most one linked definition",
                Severity::Incomplete,
            ));
        }
        for field in fields {
            let key = format!("{prefix}.{}", field.name);
            let bundle_key = bundle
                && if prefix == "criteria" {
                    matches!(field.name.as_str(), "EVM" | "PER" | "RSSI")
                        || (schema.function.interface == "IOT" && field.name == "FREQ_ERROR_KHZ")
                } else {
                    matches!(
                        field.name.as_str(),
                        "BAND" | "DATA_RATE" | "FRAME_COUNT" | "RX_TARGET_POWER"
                    ) || (schema.function.interface == "IOT"
                        && matches!(field.name.as_str(), "TECH" | "DUT_NAME" | "DUT_CASE"))
                };
            if encoding == Encoding::Named
                && !known_key(&field.name, prefix == "criteria")
                && !bundle_key
            {
                issues.push(diagnostic(
                    &key,
                    "unsupported_grammar",
                    "dictionary-to-script key mapping has not been audited",
                    Severity::Incomplete,
                ));
            }
            let Some(definition) = &field.definition else {
                issues.push(diagnostic(
                    &key,
                    "missing_definition",
                    "linked definition is missing",
                    Severity::Incomplete,
                ));
                continue;
            };
            if !matches!(
                definition.kind.as_str(),
                "string" | "int" | "double" | "list[int]"
            ) {
                issues.push(diagnostic(
                    &key,
                    "unsupported_type",
                    format!("unsupported type: {}", definition.kind),
                    Severity::Incomplete,
                ));
            }
            if !matches!(definition.cardinality.as_str(), "SINGLE" | "MULTIPLE") {
                issues.push(diagnostic(
                    &key,
                    "unsupported_cardinality",
                    "cardinality must be SINGLE or MULTIPLE",
                    Severity::Incomplete,
                ));
            }
            if let Err(message) = pattern(definition) {
                issues.push(diagnostic(
                    &key,
                    "unsupported_pattern",
                    message,
                    Severity::Incomplete,
                ));
            }
            if let Err(message) = allowed(&definition.allowed_values) {
                issues.push(diagnostic(
                    &key,
                    "unsupported_constraint",
                    message,
                    Severity::Incomplete,
                ));
            }
        }
    }
    issues
}

fn known_key(name: &str, criterion: bool) -> bool {
    if criterion {
        name == "POWER"
    } else {
        matches!(name, "ANT" | "STANDARD" | "FREQ" | "BW" | "TX_TARGET_POWER")
    }
}

pub(crate) fn parse_fields(
    raw: &str,
    fields: &[Field],
    encoding: Encoding,
    criteria: bool,
    issues: &mut Vec<Diagnostic>,
) -> BTreeMap<String, Value> {
    let mut values = BTreeMap::new();
    if raw.is_empty() {
        return values;
    }
    let prefix = if criteria { "criteria" } else { "params" };
    if encoding == Encoding::Raw {
        if let Some(field) = fields.first() {
            values.insert(field.name.clone(), parsed_value(raw, Some(field)));
        } else {
            issues.push(diagnostic(
                prefix,
                "unexpected_value",
                "no input is linked to this field",
                Severity::Error,
            ));
        }
        return values;
    }
    for assignment in raw.split('&') {
        let Some((name, value)) = assignment.split_once('=') else {
            issues.push(diagnostic(
                prefix,
                "invalid_assignment",
                "expected key=value assignments joined by &",
                Severity::Error,
            ));
            continue;
        };
        if name.trim().is_empty() || name.trim() != name || value.is_empty() || value.contains('=')
        {
            issues.push(diagnostic(
                prefix,
                "invalid_assignment",
                "assignment keys and values must be nonempty and unambiguous",
                Severity::Error,
            ));
        }
        let field = fields.iter().find(|field| field.name == name);
        if values
            .insert(name.to_string(), parsed_value(value, field))
            .is_some()
        {
            issues.push(diagnostic(
                &format!("{prefix}.{name}"),
                "duplicate_key",
                "duplicate assignment key",
                Severity::Error,
            ));
        }
    }
    values
}

fn parsed_value(raw: &str, field: Option<&Field>) -> Value {
    let multi = field
        .and_then(|field| field.definition.as_ref())
        .is_some_and(|definition| {
            definition.cardinality == "MULTIPLE" || definition.kind == "list[int]"
        });
    if multi {
        Value::Multiple(raw.split(',').map(str::to_string).collect())
    } else {
        Value::Single(raw.to_string())
    }
}

pub(crate) fn fixed_issues(request: &ComposeRequest, convention: Option<i64>) -> Vec<Diagnostic> {
    let mut issues = Vec::new();
    if request.timeout == 0 {
        issues.push(diagnostic(
            "timeout",
            "invalid_timeout",
            "timeout must be positive integer milliseconds",
            Severity::Error,
        ));
    }
    for (key, value) in [
        ("device", Some(request.device.as_str())),
        ("function", Some(request.function.as_str())),
        ("pass_path", request.pass_path.as_deref()),
        ("fail_path", request.fail_path.as_deref()),
        ("error_code", request.error_code.as_deref()),
    ] {
        if let Some(value) = value
            && value.contains(['|', '\r', '\n'])
        {
            issues.push(diagnostic(
                key,
                "reserved_character",
                "pipes and line breaks are not allowed",
                Severity::Error,
            ));
        }
    }
    match convention {
        Some(1) => {
            if request.pass_path.is_some()
                || request.fail_path.is_some()
                || request.error_code.is_some()
            {
                issues.push(diagnostic(
                    "flow",
                    "unexpected_flow",
                    "convention 1 does not accept flow or error-code fields",
                    Severity::Error,
                ));
            }
        }
        Some(2) => {
            for (key, value) in [
                ("pass_path", &request.pass_path),
                ("fail_path", &request.fail_path),
            ] {
                if value.as_ref().is_none_or(|value| value.trim().is_empty()) {
                    issues.push(diagnostic(
                        key,
                        "required",
                        "a nonempty flow target is required",
                        Severity::Error,
                    ));
                }
            }
        }
        _ => issues.push(diagnostic(
            "function",
            "unsupported_convention",
            "function convention is missing or unsupported",
            Severity::Incomplete,
        )),
    }
    issues
}

pub(crate) fn compose(schema: &FunctionSchema, request: &ComposeRequest) -> Result<ComposeResult> {
    let mut issues = fixed_issues(request, schema.function.convention);
    issues.extend(support_issues(schema));
    let encoding = profile(&schema.function);
    let parameters = if let Some(encoding) = encoding {
        emit_fields(
            &schema.parameters,
            &request.params,
            encoding,
            false,
            &mut issues,
        )
    } else {
        String::new()
    };
    let criteria = match (&request.criteria, encoding) {
        (CriteriaInput::Named(values), Some(encoding)) => {
            emit_fields(&schema.criteria, values, encoding, true, &mut issues)
        }
        (CriteriaInput::Raw(value), Some(Encoding::Raw)) => {
            if let Some(field) = schema.criteria.first() {
                emit_fields(
                    &schema.criteria,
                    &BTreeMap::from([(field.name.clone(), Value::Single(value.clone()))]),
                    Encoding::Raw,
                    true,
                    &mut issues,
                )
            } else if value.is_empty() || value == "NULL" {
                String::new()
            } else {
                issues.push(diagnostic(
                    "criteria",
                    "unknown_criteria",
                    "no raw criterion is linked to this function",
                    Severity::Error,
                ));
                String::new()
            }
        }
        (CriteriaInput::Raw(_), Some(Encoding::Named)) => {
            issues.push(diagnostic(
                "criteria",
                "invalid_shape",
                "this profile requires a named criteria map",
                Severity::Error,
            ));
            String::new()
        }
        _ => String::new(),
    };
    if issues
        .iter()
        .any(|issue| issue.severity != Severity::Warning)
    {
        return Err(Error::Validation(issues));
    }
    let mut segments = vec![
        request.device.clone(),
        schema.function.name.clone(),
        parameters,
        if criteria.is_empty() {
            "NULL".into()
        } else {
            criteria
        },
        request.timeout.to_string(),
    ];
    if schema.function.convention == Some(2) {
        segments.push(request.pass_path.clone().unwrap_or_default());
        segments.push(request.fail_path.clone().unwrap_or_default());
        segments.push(request.error_code.clone().unwrap_or_default());
    }
    Ok(ComposeResult {
        line: segments.join("|"),
        warnings: issues,
    })
}

pub(crate) fn emit_fields(
    fields: &[Field],
    values: &BTreeMap<String, Value>,
    encoding: Encoding,
    criteria: bool,
    issues: &mut Vec<Diagnostic>,
) -> String {
    let prefix = if criteria { "criteria" } else { "params" };
    let mut parts = Vec::new();
    for field in fields {
        let key = format!("{prefix}.{}", field.name);
        let Some(value) = values.get(&field.name) else {
            if field.required {
                issues.push(diagnostic(
                    &key,
                    "required",
                    "required value is missing",
                    Severity::Error,
                ));
            }
            continue;
        };
        let raw = validate_value(field, value, encoding, &key, issues);
        parts.push(if encoding == Encoding::Named {
            format!("{}={raw}", field.name)
        } else {
            raw
        });
    }
    for (name, value) in values
        .iter()
        .filter(|(name, _)| !fields.iter().any(|field| field.name == **name))
    {
        let key = format!("{prefix}.{name}");
        if criteria && encoding == Encoding::Named {
            issues.push(diagnostic(
                &key,
                "unknown_criteria_key",
                "unknown criteria key preserved without semantic validation",
                Severity::Warning,
            ));
            if name.trim().is_empty()
                || name.trim() != name
                || name.contains(['|', '\r', '\n', '&', '='])
            {
                issues.push(diagnostic(
                    &key,
                    "invalid_key",
                    "invalid criteria key",
                    Severity::Error,
                ));
            }
            let raw = match value {
                Value::Single(raw) => raw.clone(),
                Value::Multiple(values) => values.join(","),
            };
            if raw.trim().is_empty() || raw.contains(['|', '\r', '\n', '&', '=']) {
                issues.push(diagnostic(
                    &key,
                    "invalid_value",
                    "unknown criterion must still be a nonempty valid assignment value",
                    Severity::Error,
                ));
            }
            parts.push(format!("{name}={raw}"));
        } else {
            issues.push(diagnostic(
                &key,
                "unknown_parameter",
                "unknown input key",
                Severity::Error,
            ));
        }
    }
    parts.join(if encoding == Encoding::Named { "&" } else { "" })
}

fn validate_value(
    field: &Field,
    value: &Value,
    encoding: Encoding,
    key: &str,
    issues: &mut Vec<Diagnostic>,
) -> String {
    let values = match value {
        Value::Single(raw) => vec![raw.as_str()],
        Value::Multiple(values) => values.iter().map(String::as_str).collect(),
    };
    let Some(definition) = &field.definition else {
        return values.join(",");
    };
    let multi = definition.cardinality == "MULTIPLE" || definition.kind == "list[int]";
    if multi != matches!(value, Value::Multiple(_)) || values.is_empty() {
        issues.push(diagnostic(
            key,
            "cardinality",
            "SINGLE needs a string; MULTIPLE needs a nonempty string array",
            Severity::Error,
        ));
    }
    for raw in &values {
        if raw.trim().is_empty()
            || raw.contains(['|', '\r', '\n'])
            || (encoding == Encoding::Named && raw.contains(['&', '=']))
            || (multi && raw.contains(','))
        {
            issues.push(diagnostic(
                key,
                "invalid_value",
                "empty values or reserved delimiters are not allowed",
                Severity::Error,
            ));
            continue;
        }
        if raw.starts_with('*') {
            if ["*E:", "*I:", "*T:"].iter().any(|prefix| {
                raw.strip_prefix(prefix)
                    .is_some_and(|tail| !tail.trim().is_empty())
            }) {
                issues.push(diagnostic(
                    key,
                    "runtime_reference_unchecked",
                    "engine reference preserved; runtime target and value are unchecked",
                    Severity::Warning,
                ));
            } else {
                issues.push(diagnostic(
                    key,
                    "invalid_reference",
                    "expected *E:, *I:, or *T: followed by a nonempty payload",
                    Severity::Error,
                ));
            }
            continue;
        }
        let Ok(expression) = pattern(definition) else {
            continue;
        };
        let Some(captures) = expression.captures(raw) else {
            issues.push(diagnostic(
                key,
                "pattern_violation",
                format!("value does not match {}", definition.value_pattern),
                Severity::Error,
            ));
            continue;
        };
        let captured: Vec<_> = captures
            .iter()
            .skip(1)
            .flatten()
            .map(|capture| capture.as_str())
            .collect();
        let tokens = if captured.is_empty() {
            vec![*raw]
        } else {
            captured
        };
        for token in tokens {
            let numeric = if definition.unit.is_empty() {
                token
            } else {
                token.strip_suffix(&definition.unit).unwrap_or(token)
            };
            let valid_type = match definition.kind.as_str() {
                "int" | "list[int]" => numeric.parse::<i64>().is_ok(),
                "double" => numeric.parse::<f64>().is_ok_and(f64::is_finite),
                "string" => true,
                _ => false,
            };
            if !valid_type {
                issues.push(diagnostic(
                    key,
                    "type_violation",
                    format!("expected {} with unit {}", definition.kind, definition.unit),
                    Severity::Error,
                ));
                continue;
            }
            match allowed(&definition.allowed_values) {
                Ok(Allowed::Set(values))
                    if !values
                        .iter()
                        .any(|value| value == token || value == numeric) =>
                {
                    issues.push(diagnostic(
                        key,
                        "allowed_values",
                        "value is not in the allowed set",
                        Severity::Error,
                    ));
                }
                Ok(Allowed::Range(lower, upper))
                    if !numeric.parse::<f64>().is_ok_and(|number| {
                        number.is_finite() && number >= lower && number <= upper
                    }) =>
                {
                    issues.push(diagnostic(
                        key,
                        "allowed_values",
                        "value is outside the allowed numeric range",
                        Severity::Error,
                    ));
                }
                _ => {}
            }
        }
    }
    values.join(",")
}

fn pattern(definition: &Definition) -> std::result::Result<Regex, String> {
    let original = definition.value_pattern.trim();
    if original.is_empty() {
        return Err("value_pattern is missing".into());
    }
    let repetition = Regex::new(r"^<[^<>]+>(?:,\s*<[^<>]+>)+(?:\.{3}|\u{2026})$")
        .map_err(|error| error.to_string())?;
    let multi = definition.cardinality == "MULTIPLE" || definition.kind == "list[int]";
    let source = if repetition.is_match(original) {
        if !multi {
            return Err("a repeated template requires MULTIPLE cardinality".into());
        }
        "<value>"
    } else {
        original
    };
    if source.contains(['[', ']', '{', '}', '\u{2026}']) || source.contains("...") {
        return Err("optional or undocumented repetition syntax is unsupported".into());
    }
    let mut expression = String::from("\\A");
    let mut remaining = source;
    let mut count = 0;
    while let Some(start) = remaining.find('<') {
        expression.push_str(&regex::escape(&remaining[..start]));
        let tail = &remaining[start + 1..];
        let end = tail.find('>').ok_or("unterminated pattern placeholder")?;
        let name = &tail[..end];
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err("placeholder names must contain letters, digits, or underscores".into());
        }
        expression.push_str("(.+?)");
        count += 1;
        remaining = &tail[end + 1..];
    }
    if remaining.contains('>') || (multi && count != 1) {
        return Err("MULTIPLE requires a scalar or uniform repeated placeholder template".into());
    }
    expression.push_str(&regex::escape(remaining));
    expression.push_str("\\z");
    Regex::new(&expression).map_err(|error| error.to_string())
}

enum Allowed {
    Any,
    Set(Vec<String>),
    Range(f64, f64),
}

fn allowed(raw: &str) -> std::result::Result<Allowed, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Allowed::Any);
    }
    if let Some(inner) = raw
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    {
        let values: Vec<_> = inner
            .split(',')
            .map(|value| value.trim().to_string())
            .collect();
        if values.iter().any(String::is_empty) {
            return Err("allowed-value set contains an empty member".into());
        }
        return Ok(Allowed::Set(values));
    }
    if let Some(inner) = raw
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        && let Some((lower, upper)) = inner.split_once("..")
    {
        let lower = lower
            .trim()
            .parse::<f64>()
            .map_err(|_| "invalid lower bound")?;
        let upper = upper
            .trim()
            .parse::<f64>()
            .map_err(|_| "invalid upper bound")?;
        if lower.is_finite() && upper.is_finite() && lower <= upper {
            return Ok(Allowed::Range(lower, upper));
        }
    }
    Err("only explicit {sets} and [lower..upper] numeric ranges are supported".into())
}
