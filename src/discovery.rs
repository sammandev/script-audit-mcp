//! Read-only catalog discovery: Script devices, readiness, field lookups, search, and Examples.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    Engine, Result,
    devices::script_device,
    grammar::{self, BundleGrammar, Encoding},
    model::{Definition, Diagnostic, Example, Field, Function, FunctionSchema, Link, Severity},
};

/// Readiness verdicts shared with the web app's `GET /api/mcp-readiness` (web ADR-0012).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    /// Lines and bundles can be composed and validated.
    Ready,
    /// Only INI bundles can be validated.
    BundleReady,
    NotReady,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Parameter,
    Criterion,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LabelledDefinition {
    /// `global` (empty Device scope) or `scoped`.
    pub resolution: FieldResolution,
    #[serde(flatten)]
    pub definition: Definition,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DefinitionLookup {
    pub kind: FieldKind,
    pub name: String,
    /// Global first, then scoped variants by Device scope. Empty when the name is unknown.
    pub definitions: Vec<LabelledDefinition>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FieldUser {
    pub script_device: String,
    pub source: String,
    pub interface: String,
    pub name: String,
    /// Device scope of the applying link; empty for Global.
    pub link_scope: String,
    pub position: Option<i64>,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FieldUsers {
    pub kind: FieldKind,
    pub name: String,
    pub functions: Vec<FieldUser>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionFields {
    pub name: String,
    pub device_scope: String,
    pub parameters: Vec<Field>,
    pub criteria: Vec<Field>,
    /// Resolution problems; fields are empty when the links cannot be resolved.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionFieldsList {
    pub functions: Vec<FunctionFields>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceRow {
    pub script_device: String,
    pub source: String,
    pub interface: String,
    /// DLL mode suffixes accepted after `#`.
    pub mode_suffixes: Vec<String>,
    pub function_count: usize,
    pub composable_count: usize,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ReadinessCheck {
    pub ready: bool,
    pub issues: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ReadinessGrammar {
    /// `raw` or `named`.
    pub encoding: String,
    /// `line` (lines and bundles) or `bundle` (INI bundles only).
    pub scope: String,
    /// False when the built-in profiles apply to a catalog without audited grammar.
    pub audited: bool,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ReadinessField {
    pub name: String,
    /// Device scope of the link; empty for Global.
    pub device_name: String,
    pub required: bool,
    pub has_definition: bool,
    /// Audited script-key scope (`line` or `bundle`), if any.
    pub script_key_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct FieldRef {
    pub kind: FieldKind,
    pub name: String,
}

/// Where a linked field's definition resolves for its Device scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldResolution {
    /// A definition scoped to the link's device.
    Scoped,
    /// The Global definition (empty Device scope).
    Global,
    /// No definition resolves.
    Missing,
}

#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct ReadinessCounts {
    pub ready: usize,
    pub bundle_ready: usize,
    pub not_ready: usize,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceField {
    pub kind: FieldKind,
    pub name: String,
    /// Distinct resolutions across the device's Functions.
    pub resolutions: Vec<FieldResolution>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceSummary {
    #[serde(flatten)]
    pub device: DeviceRow,
    pub readiness: ReadinessCounts,
    pub fields: Vec<DeviceField>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionReadiness {
    pub script_device: String,
    pub source: String,
    pub interface: String,
    pub name: String,
    pub device_scope: String,
    pub status: Readiness,
    pub line: ReadinessCheck,
    pub bundle: ReadinessCheck,
    pub grammar: Option<ReadinessGrammar>,
    pub parameters: Vec<ReadinessField>,
    pub criteria: Vec<ReadinessField>,
    /// Fields whose dictionary-to-script key mapping has not been audited.
    pub unaudited_keys: Vec<FieldRef>,
}

fn encoding_name(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Raw => "raw",
        Encoding::Named => "named",
    }
}

fn grammar_of(function: &Function) -> Option<ReadinessGrammar> {
    if let Some(audited) = &function.audited_grammar {
        return (!audited.encoding.is_empty()).then(|| ReadinessGrammar {
            encoding: audited.encoding.clone(),
            scope: audited.scope.clone(),
            audited: true,
        });
    }
    let (encoding, scope) = match grammar::profile(function) {
        Some(encoding) => (encoding, "line"),
        None => (grammar::bundle_profile(function)?, "bundle"),
    };
    Some(ReadinessGrammar {
        encoding: encoding_name(encoding).into(),
        scope: scope.into(),
        audited: false,
    })
}

fn readiness_fields(function: &Function, fields: &[Field], criterion: bool) -> Vec<ReadinessField> {
    fields
        .iter()
        .map(|field| ReadinessField {
            name: field.name.clone(),
            device_name: field.device_name.clone(),
            required: field.required,
            has_definition: field.definition.is_some(),
            script_key_scope: function.audited_grammar.as_ref().and_then(|grammar| {
                grammar
                    .script_keys
                    .iter()
                    .find(|key| key.criterion == criterion && key.name == field.name)
                    .map(|key| key.scope.clone())
            }),
        })
        .collect()
}

fn verdict(line: &[Diagnostic], bundle: &[Diagnostic]) -> Readiness {
    if line.is_empty() {
        Readiness::Ready
    } else if bundle.is_empty() {
        Readiness::BundleReady
    } else {
        Readiness::NotReady
    }
}

impl Engine {
    /// One row per reachable Script device, sorted by source, then Interface.
    pub fn list_devices(&self) -> Result<Vec<DeviceRow>> {
        let mut devices: BTreeMap<(String, String), DeviceRow> = BTreeMap::new();
        for function in self.list_functions(None)? {
            let device = script_device(&function.source, &function.interface);
            let reachable = crate::device_target(&device).is_ok_and(|(source, interface)| {
                source == function.source && interface.eq_ignore_ascii_case(&function.interface)
            });
            if !reachable {
                continue;
            }
            let key = (
                function.source.clone(),
                function.interface.to_ascii_uppercase(),
            );
            let row = devices.entry(key).or_insert_with(|| DeviceRow {
                script_device: device,
                mode_suffixes: if function.source == "DLL" {
                    vec!["QUICK".into(), "PROXY".into()]
                } else {
                    Vec::new()
                },
                source: function.source.clone(),
                interface: function.interface.clone(),
                function_count: 0,
                composable_count: 0,
            });
            row.function_count += 1;
            row.composable_count += usize::from(function.composition_supported);
        }
        Ok(devices.into_values().collect())
    }

    /// Global and scoped definitions named `name` (case-insensitive). A Device scope keeps
    /// only the Global definition and that scope's variant.
    pub fn get_definition(
        &self,
        kind: FieldKind,
        name: &str,
        device_scope: Option<&str>,
    ) -> Result<DefinitionLookup> {
        let mut definitions: Vec<_> = self
            .definitions(kind)
            .iter()
            .filter(|definition| definition.name.eq_ignore_ascii_case(name.trim()))
            .filter(|definition| {
                device_scope.is_none_or(|scope| {
                    definition.device_name.is_empty()
                        || definition.device_name.eq_ignore_ascii_case(scope.trim())
                })
            })
            .map(|definition| LabelledDefinition {
                resolution: if definition.device_name.is_empty() {
                    FieldResolution::Global
                } else {
                    FieldResolution::Scoped
                },
                definition: definition.clone(),
            })
            .collect();
        definitions.sort_by_key(|labelled| {
            (
                !labelled.definition.device_name.is_empty(),
                labelled.definition.device_name.to_ascii_uppercase(),
            )
        });
        Ok(DefinitionLookup {
            kind,
            name: name.trim().to_string(),
            definitions,
        })
    }

    /// Functions whose applicable links reference `name`, each once. A scoped link overrides a
    /// Global one, matching `get_function`. Without a Device scope each Function's Interface applies.
    pub fn find_functions_using(
        &self,
        kind: FieldKind,
        name: &str,
        device_scope: Option<&str>,
    ) -> Result<FieldUsers> {
        let links: Vec<&Link> = self
            .links(kind)
            .iter()
            .filter(|link| link.name.eq_ignore_ascii_case(name.trim()))
            .collect();
        let mut users = Vec::new();
        for function in &self.snapshot.functions {
            let scope = device_scope.map_or(function.interface.as_str(), str::trim);
            let applying = links
                .iter()
                .filter(|link| {
                    link.function_source == function.source
                        && link.function_name == function.name
                        && (link.device_name.is_empty()
                            || link.device_name.eq_ignore_ascii_case(scope))
                })
                .max_by_key(|link| !link.device_name.is_empty());
            if let Some(link) = applying {
                users.push(FieldUser {
                    script_device: script_device(&function.source, &function.interface),
                    source: function.source.clone(),
                    interface: function.interface.clone(),
                    name: function.name.clone(),
                    link_scope: link.device_name.clone(),
                    position: link.position,
                    required: link.required,
                });
            }
        }
        users.sort_by(|left, right| {
            (&left.source, &left.interface, &left.name).cmp(&(
                &right.source,
                &right.interface,
                &right.name,
            ))
        });
        Ok(FieldUsers {
            kind,
            name: name.trim().to_string(),
            functions: users,
        })
    }

    fn definitions(&self, kind: FieldKind) -> &[Definition] {
        match kind {
            FieldKind::Parameter => &self.snapshot.parameter_definitions,
            FieldKind::Criterion => &self.snapshot.criteria_definitions,
        }
    }

    fn links(&self, kind: FieldKind) -> &[Link] {
        match kind {
            FieldKind::Parameter => &self.snapshot.parameter_links,
            FieldKind::Criterion => &self.snapshot.criteria_links,
        }
    }

    /// Resolved parameters and criteria, as `get_function` reports them, without Examples.
    /// Without `function`, lists every Function on the device; resolution failures become
    /// diagnostics so one defective Function does not hide the rest.
    pub fn list_function_fields(
        &self,
        device: &str,
        function: Option<&str>,
        device_scope: Option<&str>,
    ) -> Result<FunctionFieldsList> {
        let fields_of = |function: &Function, schema: Result<FunctionSchema>| match schema {
            Ok(schema) => FunctionFields {
                name: function.name.clone(),
                device_scope: schema.device_scope,
                parameters: schema.parameters,
                criteria: schema.criteria,
                diagnostics: Vec::new(),
            },
            Err(error) => FunctionFields {
                name: function.name.clone(),
                device_scope: device_scope
                    .unwrap_or(&function.interface)
                    .to_ascii_uppercase(),
                parameters: Vec::new(),
                criteria: Vec::new(),
                diagnostics: vec![grammar::diagnostic(
                    "function",
                    "resolution_error",
                    error.to_string(),
                    Severity::Incomplete,
                )],
            },
        };
        if let Some(name) = function {
            let function = self.resolve_function(device, name)?;
            let schema = self.linked_schema(function, device_scope)?;
            return Ok(FunctionFieldsList {
                functions: vec![fields_of(function, Ok(schema))],
            });
        }
        let mut functions = Vec::new();
        for function in self.list_functions(Some(device))? {
            let schema = self.linked_schema(&function, device_scope);
            functions.push(fields_of(&function, schema));
        }
        Ok(FunctionFieldsList { functions })
    }

    /// One Script device's row with readiness counts and the fields its Functions link.
    pub fn get_device(&self, device: &str) -> Result<DeviceSummary> {
        let functions = self.list_functions(Some(device))?;
        let (source, interface) = crate::device_target(device)?;
        let row = self
            .list_devices()?
            .into_iter()
            .find(|row| row.source == source && row.interface.eq_ignore_ascii_case(interface))
            .ok_or_else(|| crate::devices::unknown_device(device, &self.interfaces()))?;
        let mut readiness = ReadinessCounts::default();
        let mut fields: BTreeMap<FieldRef, Vec<FieldResolution>> = BTreeMap::new();
        for function in &functions {
            match self.readiness_of(function, None).status {
                Readiness::Ready => readiness.ready += 1,
                Readiness::BundleReady => readiness.bundle_ready += 1,
                Readiness::NotReady => readiness.not_ready += 1,
            }
            let Ok(schema) = self.linked_schema(function, None) else {
                continue;
            };
            let linked = schema
                .parameters
                .iter()
                .map(|field| (FieldKind::Parameter, field))
                .chain(
                    schema
                        .criteria
                        .iter()
                        .map(|field| (FieldKind::Criterion, field)),
                );
            for (kind, field) in linked {
                let resolution = match &field.definition {
                    None => FieldResolution::Missing,
                    Some(definition) if definition.device_name.is_empty() => {
                        FieldResolution::Global
                    }
                    Some(_) => FieldResolution::Scoped,
                };
                let resolutions = fields
                    .entry(FieldRef {
                        kind,
                        name: field.name.clone(),
                    })
                    .or_default();
                if !resolutions.contains(&resolution) {
                    resolutions.push(resolution);
                    resolutions.sort();
                }
            }
        }
        Ok(DeviceSummary {
            device: row,
            readiness,
            fields: fields
                .into_iter()
                .map(|(field, resolutions)| DeviceField {
                    kind: field.kind,
                    name: field.name,
                    resolutions,
                })
                .collect(),
        })
    }

    /// Reports whether one Function can be composed as a line, validated only in bundles, or neither.
    pub fn function_readiness(
        &self,
        device: &str,
        name: &str,
        device_scope: Option<&str>,
    ) -> Result<FunctionReadiness> {
        let function = self.resolve_function(device, name)?;
        Ok(self.readiness_of(function, device_scope))
    }

    pub(crate) fn readiness_of(
        &self,
        function: &Function,
        device_scope: Option<&str>,
    ) -> FunctionReadiness {
        let mut report = FunctionReadiness {
            script_device: script_device(&function.source, &function.interface),
            source: function.source.clone(),
            interface: function.interface.clone(),
            name: function.name.clone(),
            device_scope: device_scope
                .unwrap_or(&function.interface)
                .to_ascii_uppercase(),
            status: Readiness::NotReady,
            line: ReadinessCheck {
                ready: false,
                issues: Vec::new(),
            },
            bundle: ReadinessCheck {
                ready: false,
                issues: Vec::new(),
            },
            grammar: grammar_of(function),
            parameters: Vec::new(),
            criteria: Vec::new(),
            unaudited_keys: Vec::new(),
        };
        let schema = match self.linked_schema(function, device_scope) {
            Ok(schema) => schema,
            Err(error) => {
                let issue = grammar::diagnostic(
                    "function",
                    "resolution_error",
                    error.to_string(),
                    Severity::Incomplete,
                );
                report.line.issues.push(issue.clone());
                report.bundle.issues.push(issue);
                return report;
            }
        };
        report.device_scope = schema.device_scope.clone();
        report.parameters = readiness_fields(function, &schema.parameters, false);
        report.criteria = readiness_fields(function, &schema.criteria, true);
        report.line.issues = grammar::support_issues(&schema);
        report.bundle.issues = bundle_issues(&schema);
        report.line.ready = report.line.issues.is_empty();
        report.bundle.ready = report.bundle.issues.is_empty();
        report.status = verdict(&report.line.issues, &report.bundle.issues);
        let mut unaudited: Vec<_> = report
            .line
            .issues
            .iter()
            .chain(&report.bundle.issues)
            .filter(|issue| {
                issue.code == "unsupported_grammar"
                    && issue.message == "dictionary-to-script key mapping has not been audited"
            })
            .filter_map(|issue| {
                let (prefix, name) = issue.field.split_once('.')?;
                Some(FieldRef {
                    kind: if prefix == "criteria" {
                        FieldKind::Criterion
                    } else {
                        FieldKind::Parameter
                    },
                    name: name.to_string(),
                })
            })
            .collect();
        unaudited.sort();
        unaudited.dedup();
        report.unaudited_keys = unaudited;
        report
    }

    /// Readiness for a `list_functions` row whose line composition support is already known.
    pub(crate) fn row_readiness(&self, function: &Function, composable: bool) -> Readiness {
        if composable {
            return Readiness::Ready;
        }
        if grammar::bundle_profile(function).is_none() {
            return Readiness::NotReady;
        }
        match self.linked_schema(function, None) {
            Ok(schema) if bundle_issues(&schema).is_empty() => Readiness::BundleReady,
            _ => Readiness::NotReady,
        }
    }
}

fn bundle_issues(schema: &FunctionSchema) -> Vec<Diagnostic> {
    BundleGrammar::new(schema).support_issues().to_vec()
}

/// Keys a `list_functions` row may carry; `fields` selects a subset.
pub const FUNCTION_ROW_FIELDS: &[&str] = &[
    "source",
    "interface",
    "name",
    "description",
    "convention",
    "category",
    "execution_role",
    "execution_phase",
    "composition_supported",
    "script_device",
    "readiness",
];

pub const MAX_PAGE_SIZE: u32 = 500;
const CURSOR_PREFIX: &str = "fn1.";
const DEFAULT_SEARCH_LIMIT: u32 = 20;
pub const MAX_SEARCH_LIMIT: u32 = 100;
const DEFAULT_EXAMPLE_LIMIT: u32 = 50;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    Function,
    Parameter,
    Criterion,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    /// Whitespace-separated terms; every term must match a name or description (case-insensitive).
    pub query: String,
    /// Restrict hits to these kinds; omit for all.
    pub kinds: Option<Vec<SearchKind>>,
    /// Maximum hits, 1 to 100 (default 20).
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SearchHit {
    pub kind: SearchKind,
    pub name: String,
    /// Script device of a Function hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_device: Option<String>,
    /// Device scope of a parameter or criterion definition; empty for Global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_scope: Option<String>,
    /// `name` or `description`.
    pub matched_in: String,
    pub snippet: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SearchResults {
    pub hits: Vec<SearchHit>,
    /// Matches before `limit` was applied.
    pub total: usize,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExampleQuery {
    /// Script device token; an Interface name is accepted as an alias.
    pub device: Option<String>,
    /// Function name, matched case-insensitively.
    pub function: Option<String>,
    /// Case-insensitive text matched against the script or its meaning.
    pub query: Option<String>,
    /// Opaque `next_cursor` from a previous page.
    pub cursor: Option<String>,
    /// Page size, 1 to 500 (default 50).
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ExamplePage {
    pub examples: Vec<Example>,
    /// Present while more Examples remain; pass it back as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `list_functions` inputs. Filters combine with AND; omitting every input lists all Functions.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionQuery {
    /// Script device token (first line field), e.g. `SSH` or `DLLWIFI_TEST`. Not a Device scope.
    pub device: Option<String>,
    /// Category, matched case-insensitively.
    pub category: Option<String>,
    /// Execution phase, matched case-insensitively.
    pub execution_phase: Option<String>,
    /// Only Functions that `compose_line` supports.
    pub composable_only: Option<bool>,
    /// Opaque `next_cursor` from a previous page.
    pub cursor: Option<String>,
    /// Page size, 1 to 500. Omit to return every match.
    pub limit: Option<u32>,
    /// Row keys to return, from: source, interface, name, description, convention, category,
    /// execution_role, execution_phase, composition_supported, script_device, readiness.
    pub fields: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionPage {
    pub functions: Vec<serde_json::Map<String, serde_json::Value>>,
    /// Present while more rows remain; pass it back as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Serialize)]
struct FunctionRow<'function> {
    #[serde(flatten)]
    function: &'function Function,
    script_device: String,
    readiness: Readiness,
}

fn invalid(field: &str, message: impl Into<String>) -> crate::Error {
    crate::Error::InvalidInput {
        field: field.into(),
        message: message.into(),
    }
}

fn matches(value: &str, filter: Option<&String>) -> bool {
    filter.is_none_or(|filter| value.eq_ignore_ascii_case(filter.trim()))
}

impl Engine {
    /// `list_functions` rows with Script device and readiness, filtered and paged.
    pub fn list_function_rows(&self, query: &FunctionQuery) -> Result<FunctionPage> {
        if let Some(fields) = &query.fields
            && let Some(unknown) = fields
                .iter()
                .find(|field| !FUNCTION_ROW_FIELDS.contains(&field.as_str()))
        {
            return Err(invalid(
                "fields",
                format!(
                    "unknown row field {unknown:?}; expected one of {}",
                    FUNCTION_ROW_FIELDS.join(", ")
                ),
            ));
        }
        let window = Window::new(query.cursor.as_deref(), query.limit, None)?;
        let mut rows = Vec::new();
        for function in self.list_functions(query.device.as_deref())? {
            if !matches(&function.category, query.category.as_ref())
                || !matches(&function.execution_phase, query.execution_phase.as_ref())
                || (query.composable_only == Some(true) && !function.composition_supported)
            {
                continue;
            }
            let readiness = self.row_readiness(&function, function.composition_supported);
            rows.push((function, readiness));
        }
        let (rows, next_cursor) = window.apply(rows);
        let functions = rows
            .iter()
            .map(|(function, readiness)| {
                let row = FunctionRow {
                    function,
                    script_device: script_device(&function.source, &function.interface),
                    readiness: *readiness,
                };
                let mut row = match serde_json::to_value(row) {
                    Ok(serde_json::Value::Object(row)) => row,
                    Ok(_) => serde_json::Map::new(),
                    Err(error) => return Err(crate::Error::Knowledge(error.to_string())),
                };
                if let Some(fields) = &query.fields {
                    row.retain(|key, _| fields.iter().any(|field| field == key));
                }
                Ok(row)
            })
            .collect::<Result<_>>()?;
        Ok(FunctionPage {
            functions,
            next_cursor,
        })
    }

    /// Ranked case-insensitive search over Function and field names and descriptions.
    /// Every query term must match; name matches rank above description matches.
    pub fn search_catalog(&self, query: &SearchQuery) -> Result<SearchResults> {
        let terms: Vec<String> = query
            .query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        if terms.is_empty() {
            return Err(invalid("query", "must contain at least one search term"));
        }
        let limit = match query.limit {
            None => DEFAULT_SEARCH_LIMIT,
            Some(limit) if (1..=MAX_SEARCH_LIMIT).contains(&limit) => limit,
            Some(_) => {
                return Err(invalid(
                    "limit",
                    format!("must be between 1 and {MAX_SEARCH_LIMIT}"),
                ));
            }
        };
        let wanted = |kind| {
            query
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&kind))
        };
        let mut hits = Vec::new();
        if wanted(SearchKind::Function) {
            for function in &self.snapshot.functions {
                if let Some((rank, matched_in, snippet)) =
                    rank(&terms, &function.name, &function.description)
                {
                    hits.push((
                        rank,
                        SearchHit {
                            kind: SearchKind::Function,
                            name: function.name.clone(),
                            script_device: Some(script_device(
                                &function.source,
                                &function.interface,
                            )),
                            device_scope: None,
                            matched_in,
                            snippet,
                        },
                    ));
                }
            }
        }
        for (kind, definitions) in [
            (SearchKind::Parameter, &self.snapshot.parameter_definitions),
            (SearchKind::Criterion, &self.snapshot.criteria_definitions),
        ] {
            if !wanted(kind) {
                continue;
            }
            for definition in definitions {
                if let Some((rank, matched_in, snippet)) =
                    rank(&terms, &definition.name, &definition.description)
                {
                    hits.push((
                        rank,
                        SearchHit {
                            kind,
                            name: definition.name.clone(),
                            script_device: None,
                            device_scope: Some(definition.device_name.clone()),
                            matched_in,
                            snippet,
                        },
                    ));
                }
            }
        }
        hits.sort_by(|(left_rank, left), (right_rank, right)| {
            (
                left_rank,
                left.kind,
                &left.name,
                &left.script_device,
                &left.device_scope,
            )
                .cmp(&(
                    right_rank,
                    right.kind,
                    &right.name,
                    &right.script_device,
                    &right.device_scope,
                ))
        });
        let total = hits.len();
        hits.truncate(limit as usize);
        Ok(SearchResults {
            hits: hits.into_iter().map(|(_, hit)| hit).collect(),
            total,
        })
    }

    /// Stored Examples filtered by Script device and Function (as `get_function` matches them)
    /// and by a case-insensitive text query over script and meaning.
    pub fn list_examples(&self, query: &ExampleQuery) -> Result<ExamplePage> {
        let window = Window::new(
            query.cursor.as_deref(),
            query.limit,
            Some(DEFAULT_EXAMPLE_LIMIT),
        )?;
        let mut examples: Vec<Example> = match query.device.as_deref() {
            Some(device) => {
                let functions: Vec<&Function> = match query.function.as_deref() {
                    Some(name) => vec![self.resolve_function(device, name)?],
                    None => {
                        self.list_functions(Some(device))?;
                        let (source, interface) = crate::device_target(device)?;
                        self.snapshot
                            .functions
                            .iter()
                            .filter(|function| {
                                function.source == source
                                    && function.interface.eq_ignore_ascii_case(interface)
                            })
                            .collect()
                    }
                };
                functions
                    .into_iter()
                    .flat_map(|function| self.function_examples(function, &function.interface))
                    .collect()
            }
            None => {
                self.snapshot
                    .examples
                    .iter()
                    .filter(|example| {
                        query.function.as_deref().is_none_or(|name| {
                            example.function_name.eq_ignore_ascii_case(name.trim())
                        })
                    })
                    .cloned()
                    .collect()
            }
        };
        if let Some(text) = query
            .query
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        {
            let text = text.to_lowercase();
            examples.retain(|example| {
                example.script.to_lowercase().contains(&text)
                    || example.meaning.to_lowercase().contains(&text)
            });
        }
        examples.sort_by(|left, right| {
            (
                &left.function_source,
                left.device_name.to_ascii_uppercase(),
                &left.function_name,
                &left.script,
            )
                .cmp(&(
                    &right.function_source,
                    right.device_name.to_ascii_uppercase(),
                    &right.function_name,
                    &right.script,
                ))
        });
        examples.dedup_by(|left, right| {
            left.function_source == right.function_source
                && left.function_name == right.function_name
                && left.script == right.script
                && left.device_name.eq_ignore_ascii_case(&right.device_name)
        });
        let (examples, next_cursor) = window.apply(examples);
        Ok(ExamplePage {
            examples,
            next_cursor,
        })
    }
}

/// Offset paging with opaque cursors. Clients must treat cursors as opaque (MCP pagination).
struct Window {
    offset: usize,
    limit: Option<usize>,
}

impl Window {
    fn new(cursor: Option<&str>, limit: Option<u32>, default: Option<u32>) -> Result<Self> {
        if let Some(limit) = limit
            && !(1..=MAX_PAGE_SIZE).contains(&limit)
        {
            return Err(invalid(
                "limit",
                format!("must be between 1 and {MAX_PAGE_SIZE}"),
            ));
        }
        let offset = match cursor {
            None => 0,
            Some(cursor) => cursor
                .strip_prefix(CURSOR_PREFIX)
                .and_then(|offset| offset.parse::<usize>().ok())
                .ok_or_else(|| invalid("cursor", "not a cursor returned by this tool"))?,
        };
        Ok(Self {
            offset,
            limit: limit.or(default).map(|limit| limit as usize),
        })
    }

    fn apply<Row>(&self, mut rows: Vec<Row>) -> (Vec<Row>, Option<String>) {
        let end = self
            .limit
            .map_or(rows.len(), |limit| self.offset.saturating_add(limit))
            .min(rows.len());
        let next_cursor = (end < rows.len()).then(|| format!("{CURSOR_PREFIX}{end}"));
        rows.truncate(end);
        let page = rows.split_off(self.offset.min(end));
        (page, next_cursor)
    }
}

/// `(rank, matched_in, snippet)` when every term matches the name or description.
fn rank(terms: &[String], name: &str, description: &str) -> Option<(u8, String, String)> {
    let lower_name = name.to_lowercase();
    let lower_description = description.to_lowercase();
    if !terms
        .iter()
        .all(|term| lower_name.contains(term) || lower_description.contains(term))
    {
        return None;
    }
    let phrase = terms.join(" ");
    if lower_name == phrase {
        return Some((0, "name".into(), name.into()));
    }
    if terms.iter().any(|term| lower_name.contains(term)) {
        return Some((1, "name".into(), name.into()));
    }
    Some((2, "description".into(), snippet(description, &terms[0])))
}

/// Up to about 120 characters of `text` around the first occurrence of `term`.
fn snippet(text: &str, term: &str) -> String {
    const WIDTH: usize = 120;
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= WIDTH {
        return text.into();
    }
    let lower: Vec<char> = text.to_lowercase().chars().collect();
    let needle: Vec<char> = term.chars().collect();
    let found = if lower.len() == chars.len() {
        lower
            .windows(needle.len().max(1))
            .position(|window| window == needle.as_slice())
            .unwrap_or(0)
    } else {
        0
    };
    let start = found.saturating_sub(WIDTH / 3);
    let end = (start + WIDTH).min(chars.len());
    let mut excerpt: String = chars[start..end].iter().collect();
    if start > 0 {
        excerpt.insert(0, '…');
    }
    if end < chars.len() {
        excerpt.push('…');
    }
    excerpt
}

/// How a parsed parameter or criterion payload is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    /// `KEY=value` assignments joined by `&`.
    Named,
    /// One raw value bound to the Function's single linked field.
    Raw,
    /// The `NULL` criterion placeholder.
    Null,
    /// An empty payload.
    Empty,
    /// The Function or its grammar is unresolved, so the payload is not split.
    Unknown,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ParsedField {
    /// Assignment key, or the linked field name for a raw payload.
    pub name: String,
    pub value: String,
    /// True when the Function links this field.
    pub linked: bool,
    pub resolution: FieldResolution,
    pub definition: Option<Definition>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ParsedPayload {
    pub raw: String,
    pub encoding: PayloadEncoding,
    pub fields: Vec<ParsedField>,
    /// Whole-section `*V:Section#` references, preserved unresolved.
    pub section_references: Vec<String>,
}

/// A Script line split into its fields and annotated with resolved definitions.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ParsedLine {
    pub line: String,
    pub status: crate::model::ValidationStatus,
    pub device: Option<String>,
    pub function: Option<String>,
    pub source: Option<String>,
    pub interface: Option<String>,
    pub convention: Option<i64>,
    pub parameters: ParsedPayload,
    pub criteria: ParsedPayload,
    pub timeout: Option<String>,
    pub pass_path: Option<String>,
    pub fail_path: Option<String>,
    pub error_code: Option<String>,
    /// The same diagnostics `validate_line` reports.
    pub diagnostics: Vec<Diagnostic>,
}

impl Engine {
    /// Splits a Script line and annotates each parameter and criterion with its definition.
    pub fn parse_line(&self, line: &str, device_scope: Option<&str>) -> Result<ParsedLine> {
        let report = self.validate_line(line, device_scope)?;
        let segments: Vec<&str> = line.trim_end_matches(['\r', '\n']).split('|').collect();
        let segment = |index: usize| segments.get(index).map(|value| (*value).to_string());
        let function = match (segments.first(), segments.get(1)) {
            (Some(device), Some(function)) => self.resolve_function(device, function).ok(),
            _ => None,
        };
        let schema = match (segments.first(), segments.get(1)) {
            (Some(device), Some(function)) => {
                self.get_function(device, function, device_scope).ok()
            }
            _ => None,
        };
        let encoding = function.and_then(grammar::profile);
        let payload = |index: usize, criterion: bool| {
            let raw = segments.get(index).copied().unwrap_or_default();
            let fields = schema.as_ref().map(|schema| {
                if criterion {
                    schema.criteria.as_slice()
                } else {
                    schema.parameters.as_slice()
                }
            });
            parse_payload(raw, criterion, encoding, fields)
        };
        Ok(ParsedLine {
            line: line.into(),
            status: report.status,
            device: segment(0),
            function: segment(1),
            source: function.map(|function| function.source.clone()),
            interface: function.map(|function| function.interface.clone()),
            convention: function.and_then(|function| function.convention),
            parameters: payload(2, false),
            criteria: payload(3, true),
            timeout: segment(4),
            pass_path: segment(5),
            fail_path: segment(6),
            error_code: segment(7),
            diagnostics: report.diagnostics,
        })
    }
}

fn parse_payload(
    raw: &str,
    criterion: bool,
    encoding: Option<Encoding>,
    fields: Option<&[Field]>,
) -> ParsedPayload {
    let mut payload = ParsedPayload {
        raw: raw.into(),
        encoding: PayloadEncoding::Unknown,
        fields: Vec::new(),
        section_references: Vec::new(),
    };
    if criterion && raw == grammar::NULL_CRITERION {
        payload.encoding = PayloadEncoding::Null;
        return payload;
    }
    if raw.is_empty() {
        payload.encoding = PayloadEncoding::Empty;
        return payload;
    }
    let linked = fields.unwrap_or_default();
    match encoding {
        Some(Encoding::Raw) => {
            payload.encoding = PayloadEncoding::Raw;
            if let Some(field) = linked.first() {
                payload
                    .fields
                    .push(annotate(field.name.clone(), raw, Some(field)));
            }
        }
        Some(Encoding::Named) => {
            payload.encoding = PayloadEncoding::Named;
            for entry in raw.split('&') {
                if grammar::is_section_reference(entry) {
                    payload.section_references.push(entry.into());
                    continue;
                }
                let (name, value) = entry.split_once('=').unwrap_or((entry, ""));
                let field = linked.iter().find(|field| field.name == name);
                payload.fields.push(annotate(name.into(), value, field));
            }
        }
        None => {}
    }
    payload
}

fn annotate(name: String, value: &str, field: Option<&Field>) -> ParsedField {
    let definition = field.and_then(|field| field.definition.clone());
    let resolution = match &definition {
        None => FieldResolution::Missing,
        Some(definition) if definition.device_name.is_empty() => FieldResolution::Global,
        Some(_) => FieldResolution::Scoped,
    };
    ParsedField {
        name,
        value: value.into(),
        linked: field.is_some(),
        resolution,
        definition,
    }
}

#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct CatalogCounts {
    pub functions: usize,
    pub script_devices: usize,
    pub parameter_definitions: usize,
    pub criteria_definitions: usize,
    pub parameter_links: usize,
    pub criteria_links: usize,
    pub examples: usize,
    /// Functions carrying an audited grammar row.
    pub audited_grammars: usize,
    pub script_key_audits: usize,
}

/// Catalog identity for caching: contract, revision, and row counts (ADR 0008).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct CatalogInfo {
    /// `mcp_v1` when audited grammar is present, otherwise `legacy`.
    pub contract: String,
    /// `sha256:` followed by the hex digest of the canonical full Snapshot.
    pub revision: String,
    pub revision_source: String,
    pub server_version: String,
    pub counts: CatalogCounts,
}

impl Engine {
    /// Reports the catalog contract, a content-hash revision, and entity counts.
    pub fn catalog_info(&self) -> Result<CatalogInfo> {
        use sha2::{Digest, Sha256};

        let snapshot = &self.snapshot;
        // Audited grammar is `serde(skip)` on Function, so hash it alongside the Snapshot.
        let grammars: Vec<_> = snapshot
            .functions
            .iter()
            .map(|function| {
                function.audited_grammar.as_ref().map(|grammar| {
                    serde_json::json!({
                        "encoding": grammar.encoding,
                        "scope": grammar.scope,
                        "script_keys": grammar.script_keys.iter().map(|key| serde_json::json!({
                            "criterion": key.criterion,
                            "name": key.name,
                            "scope": key.scope,
                        })).collect::<Vec<_>>(),
                    })
                })
            })
            .collect();
        let canonical = serde_json::to_vec(&serde_json::json!({
            "snapshot": snapshot,
            "audited_grammars": grammars,
        }))
        .map_err(|error| crate::Error::Knowledge(format!("catalog hash: {error}")))?;
        let revision = Sha256::digest(&canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let audited: Vec<_> = snapshot
            .functions
            .iter()
            .filter_map(|function| function.audited_grammar.as_ref())
            .collect();
        Ok(CatalogInfo {
            contract: if audited.is_empty() {
                "legacy"
            } else {
                "mcp_v1"
            }
            .into(),
            revision: format!("sha256:{revision}"),
            revision_source: "content_hash".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
            counts: CatalogCounts {
                functions: snapshot.functions.len(),
                script_devices: self.list_devices()?.len(),
                parameter_definitions: snapshot.parameter_definitions.len(),
                criteria_definitions: snapshot.criteria_definitions.len(),
                parameter_links: snapshot.parameter_links.len(),
                criteria_links: snapshot.criteria_links.len(),
                examples: snapshot.examples.len(),
                audited_grammars: audited.len(),
                script_key_audits: audited
                    .iter()
                    .map(|grammar| grammar.script_keys.len())
                    .sum(),
            },
        })
    }
}
