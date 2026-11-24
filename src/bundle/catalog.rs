use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};

use crate::{
    Engine, Error, device_target, function_lookup_key, grammar,
    model::{Diagnostic, Field, Severity},
};

use super::{BundleDiagnostic, ExecutionRow, semantics::has_reference};

pub(super) fn validate(
    engine: &Engine,
    execution: &[ExecutionRow],
    scope: Option<&str>,
    diagnostics: &mut Vec<BundleDiagnostic>,
) {
    let mut schemas = HashMap::new();
    for row in execution {
        if row.device.eq_ignore_ascii_case("MACRO") {
            continue;
        }
        let mut issues = Vec::new();
        let device = if row.device.starts_with("DLL")
            && let Some((device, mode)) = row.device.split_once('#')
        {
            if !matches!(mode, "QUICK" | "PROXY") {
                issues.push(grammar::diagnostic("device", "CATALOG_DISPATCH_UNCHECKED", "Function identity is resolved separately; the supplied dispatch mode remains unaudited.", Severity::Incomplete));
            }
            device
        } else {
            &row.device
        };
        if has_reference(device) || has_reference(&row.function) {
            diagnostics.push(
                BundleDiagnostic::new(
                    "catalog",
                    "CATALOG_IDENTITY_UNCHECKED",
                    "Runtime-dependent Function identity cannot be resolved against the catalog.",
                )
                .at(&row.file, row.line, Some(&row.section), Some(&row.row))
                .field("function", None)
                .unchecked(),
            );
            continue;
        }
        let resolved = match device_target(device) {
            Ok((source, interface)) => {
                match schemas.entry(function_lookup_key(source, interface, &row.function)) {
                    Entry::Occupied(cached) => Ok(cached.into_mut()),
                    Entry::Vacant(slot) => {
                        engine
                            .resolve_function(device, &row.function)
                            .map(|function| {
                                slot.insert(
                                    engine
                                        .linked_schema(function, scope)
                                        .map(|schema| {
                                            let grammar = grammar::BundleGrammar::new(&schema);
                                            (schema, grammar)
                                        })
                                        .map_err(|error| {
                                            (grammar::bundle_profile(function), error)
                                        }),
                                )
                            })
                    }
                }
            }
            Err(error) => Err(error),
        };
        let prepared = match &resolved {
            Ok(entry) => entry
                .as_ref()
                .map_err(|(encoding, error)| (*encoding, error)),
            Err(error) => Err((None, error)),
        };
        match prepared {
            Ok((schema, grammar)) => {
                issues.extend(grammar.payload_support_issues(
                    schema,
                    &row.parameters,
                    &row.criteria,
                ));
                for (raw, fields, criteria) in [
                    (row.parameters.as_str(), schema.parameters.as_slice(), false),
                    (row.criteria.as_str(), schema.criteria.as_slice(), true),
                ] {
                    validate_payload(raw, fields, grammar, criteria, &mut issues);
                }
            }
            Err((encoding, error)) => {
                if encoding == Some(grammar::Encoding::Named) {
                    for (raw, criteria) in [(&row.parameters, false), (&row.criteria, true)] {
                        for assignment in raw.split('&') {
                            validate_unresolved_assignment(assignment, criteria, &mut issues);
                        }
                        let assignments = raw
                            .split('&')
                            .filter(|assignment| {
                                !has_reference(
                                    assignment
                                        .split_once('=')
                                        .map_or(*assignment, |(name, _)| name),
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("&");
                        if !assignments.is_empty() && assignments != "NULL" {
                            grammar::parse_fields(
                                &assignments,
                                &[],
                                grammar::Encoding::Named,
                                criteria,
                                &mut issues,
                            );
                        }
                    }
                }
                let field = match error {
                    Error::InvalidInput { field, .. } => field.as_str(),
                    _ => "function",
                };
                issues.push(grammar::diagnostic(
                    field,
                    error.code(),
                    error.to_string(),
                    if matches!(error, Error::Knowledge(_) | Error::UnsupportedGrammar(_)) {
                        Severity::Incomplete
                    } else {
                        Severity::Error
                    },
                ));
            }
        }
        for Diagnostic {
            field,
            code,
            message,
            severity,
        } in issues
        {
            let evidence = format!(
                "execution={}; call_site={}",
                row.id,
                row.call_site.as_deref().unwrap_or("none")
            );
            let mut issue = BundleDiagnostic::new("catalog", &code, &message)
                .at(&row.file, row.line, Some(&row.section), Some(&row.row))
                .field(&field, Some(&evidence));
            issue.severity = match severity {
                Severity::Error => "error",
                Severity::Warning if code != "unknown_criteria_key" => "warning",
                Severity::Warning | Severity::Incomplete => "unsupported",
            };
            diagnostics.push(issue);
        }
    }
}

fn validate_payload(
    raw: &str,
    fields: &[Field],
    grammar: &grammar::BundleGrammar,
    criteria: bool,
    issues: &mut Vec<Diagnostic>,
) {
    let prefix = if criteria { "criteria" } else { "params" };
    let raw = if raw == "NULL" { "" } else { raw };
    let Some(encoding) = grammar.encoding() else {
        if raw.is_empty() {
            for field in fields.iter().filter(|field| field.required) {
                issues.push(grammar::diagnostic(
                    &format!("{prefix}.{}", field.name),
                    "required",
                    "required value is missing",
                    Severity::Error,
                ));
            }
        }
        return;
    };
    if has_reference(raw) {
        issues.push(grammar::diagnostic(
            prefix,
            "CATALOG_VALUE_UNCHECKED",
            "Unresolved bundle or runtime values cannot establish catalog compatibility.",
            Severity::Incomplete,
        ));
        if encoding == grammar::Encoding::Raw {
            return;
        }
    }
    let mut check_fields = fields.to_vec();
    let mut literal_assignments = Vec::new();
    let mut seen = HashSet::new();
    let mut dynamic_keys = false;
    if encoding == grammar::Encoding::Named && !raw.is_empty() {
        for assignment in raw.split('&') {
            validate_unresolved_assignment(assignment, criteria, issues);
            let Some((name, value)) = assignment.split_once('=') else {
                if has_reference(assignment) {
                    dynamic_keys = true;
                } else {
                    literal_assignments.push(assignment.to_string());
                }
                continue;
            };
            if has_reference(name) {
                dynamic_keys = true;
                continue;
            }
            if !seen.insert(name) {
                issues.push(grammar::diagnostic(
                    &format!("{prefix}.{name}"),
                    "duplicate_key",
                    "duplicate assignment key",
                    Severity::Error,
                ));
            }
            if !has_reference(value) {
                literal_assignments.push(assignment.to_string());
                continue;
            }
            let Some(field) = fields.iter().find(|field| field.name == name) else {
                issues.push(grammar::diagnostic(
                    &format!("{prefix}.{name}"),
                    if criteria {
                        "unknown_criteria_key"
                    } else {
                        "unknown_parameter"
                    },
                    "Unknown dictionary key has an unresolved value.",
                    if criteria {
                        Severity::Incomplete
                    } else {
                        Severity::Error
                    },
                ));
                continue;
            };
            let literals = value
                .split(',')
                .filter(|value| !has_reference(value))
                .collect::<Vec<_>>();
            if field.definition.as_ref().is_some_and(|definition| {
                definition.cardinality == "MULTIPLE" || definition.kind == "list[int]"
            }) && !literals.is_empty()
            {
                literal_assignments.push(format!("{name}={}", literals.join(",")));
            } else {
                check_fields.retain(|field| field.name != name);
            }
        }
    }
    for field in &mut check_fields {
        if dynamic_keys {
            field.required = false;
        }
        if field.definition.as_ref().is_some_and(|definition| {
            !matches!(
                definition.kind.as_str(),
                "string" | "int" | "double" | "list[int]"
            ) || !matches!(definition.cardinality.as_str(), "SINGLE" | "MULTIPLE")
        }) {
            field.definition = None;
        }
    }
    let checked = if encoding == grammar::Encoding::Named {
        literal_assignments.join("&")
    } else {
        raw.to_string()
    };
    let values = if checked.is_empty() {
        BTreeMap::new()
    } else {
        let mut literal_issues = Vec::new();
        let values = grammar::parse_fields(
            &checked,
            &check_fields,
            encoding,
            criteria,
            &mut literal_issues,
        );
        issues.extend(
            literal_issues
                .into_iter()
                .filter(|issue| issue.code != "duplicate_key"),
        );
        values
    };
    grammar.emit_fields(&check_fields, &values, encoding, criteria, issues);
}

fn validate_unresolved_assignment(assignment: &str, criteria: bool, issues: &mut Vec<Diagnostic>) {
    if has_reference(assignment) && assignment.contains('=') {
        let mut syntax = Vec::new();
        grammar::parse_fields(
            assignment,
            &[],
            grammar::Encoding::Named,
            criteria,
            &mut syntax,
        );
        issues.extend(
            syntax
                .into_iter()
                .filter(|issue| issue.code == "invalid_assignment"),
        );
    }
}
