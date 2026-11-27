mod autofix;
pub mod bundle;
pub mod devices;
pub mod discovery;
mod grammar;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod model;
#[cfg(feature = "database")]
pub mod postgres;
#[cfg(feature = "legacy-sqlite")]
pub mod sqlite;

use std::collections::{BTreeMap, HashMap};
use std::num::IntErrorKind;

use model::{
    ComposeRequest, ComposeResult, CriteriaInput, CriteriaSuggestions, Definition, Diagnostic,
    Field, Function, FunctionSchema, Link, Severity, Snapshot, ValidationReport, ValidationStatus,
};
pub(crate) use script_checker::parser::common::is_comment as is_commented_line;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown device: {device}")]
    UnknownDevice {
        device: String,
        candidates: Vec<String>,
    },
    /// `candidates` lists close Script devices when the device itself is unknown.
    #[error("unknown function: {name}")]
    UnknownFunction {
        name: String,
        candidates: Vec<String>,
    },
    #[error("invalid {field}: {message}")]
    InvalidInput { field: String, message: String },
    #[error("ambiguous function: {0}")]
    AmbiguousFunction(String),
    #[error("unsupported grammar: {0}")]
    UnsupportedGrammar(String),
    #[error("knowledge database: {0}")]
    Knowledge(String),
    #[error("script validation failed")]
    Validation(Vec<Diagnostic>),
    #[error("catalog file: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "database")]
    #[error("knowledge database: {0}")]
    Database(#[from] ::postgres::Error),
    #[cfg(feature = "legacy-sqlite")]
    #[error("legacy knowledge database: {0}")]
    LegacyDatabase(#[from] rusqlite::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownDevice { .. } => "unknown_device",
            Self::UnknownFunction { .. } => "unknown_function",
            Self::InvalidInput { .. } => "invalid_input",
            Self::AmbiguousFunction(_) => "ambiguous_function",
            Self::UnsupportedGrammar(_) => "unsupported_grammar",
            Self::Knowledge(_) => "knowledge_error",
            Self::Validation(_) => "validation_failed",
            Self::Io(_) => "file_error",
            #[cfg(feature = "database")]
            Self::Database(_) => "database_error",
            #[cfg(feature = "legacy-sqlite")]
            Self::LegacyDatabase(_) => "database_error",
        }
    }

    /// Script devices suggested by `unknown_device` and `unknown_function` errors.
    pub fn candidates(&self) -> &[String] {
        match self {
            Self::UnknownDevice { candidates, .. } | Self::UnknownFunction { candidates, .. } => {
                candidates
            }
            _ => &[],
        }
    }

    /// Fills empty suggestions; errors that already carry suggestions keep them.
    pub(crate) fn with_candidates(mut self, suggested: Vec<String>) -> Self {
        if let Self::UnknownDevice { candidates, .. } | Self::UnknownFunction { candidates, .. } =
            &mut self
            && candidates.is_empty()
        {
            *candidates = suggested;
        }
        self
    }
}

pub type Result<Value> = std::result::Result<Value, Error>;

pub trait Catalog: Send + Sync {
    fn snapshot(&self) -> Result<Snapshot>;

    /// A full snapshot that may omit Examples, for operations that never return them.
    fn snapshot_without_examples(&self) -> Result<Snapshot> {
        self.snapshot()
    }

    /// A snapshot holding the rows needed by `Engine::list_functions(Some(device))`.
    fn device_snapshot(&self, _device: &str) -> Result<Snapshot> {
        self.snapshot()
    }

    /// A snapshot holding at least every row `Engine::get_function(device, name, _)` reads.
    fn function_snapshot(&self, _device: &str, _name: &str) -> Result<Snapshot> {
        self.snapshot()
    }

    /// Like `function_snapshot`, but may omit Examples.
    fn function_snapshot_without_examples(&self, device: &str, name: &str) -> Result<Snapshot> {
        self.function_snapshot(device, name)
    }

    /// Distinct `(source, interface)` pairs, read only after a scoped lookup misses.
    fn interfaces(&self) -> Result<Vec<(String, String)>> {
        Ok(devices::interfaces(
            &self.snapshot_without_examples()?.functions,
        ))
    }
}

pub struct Engine {
    snapshot: Snapshot,
}

impl Engine {
    pub fn new(snapshot: Snapshot) -> Self {
        Self { snapshot }
    }

    pub fn compose_line(&self, request: ComposeRequest) -> Result<ComposeResult> {
        let schema = self.get_function(
            &request.device,
            &request.function,
            request.device_scope.as_deref(),
        )?;
        grammar::compose(&schema, &request, false)
    }

    pub fn validate_line(
        &self,
        line: &str,
        device_scope: Option<&str>,
    ) -> Result<ValidationReport> {
        let segments: Vec<&str> = line.trim_end_matches(['\r', '\n']).split('|').collect();
        let mut diagnostics = Vec::new();
        if is_commented_line(line) {
            diagnostics.push(grammar::diagnostic(
                "line",
                "commented_line",
                "line is commented out with ';' or '//' and the tester skips it; remove the comment prefix to validate the row",
                Severity::Error,
            ));
            return Ok(validation_report(line, diagnostics));
        }
        if line.contains(['\r', '\n']) {
            diagnostics.push(grammar::diagnostic(
                "line",
                "reserved_character",
                "a line must not contain line breaks",
                Severity::Error,
            ));
        }
        if !is_supported_line_width(segments.len()) {
            diagnostics.push(grammar::diagnostic(
                "line",
                "field_count",
                "expected 5, 7, 8, or 9 pipe-delimited fields",
                Severity::Error,
            ));
            return Ok(validation_report(line, diagnostics));
        }
        let (timeout, timeout_overflowed) = if segments[4].bytes().all(|byte| byte.is_ascii_digit())
        {
            match segments[4].parse::<u64>() {
                Ok(timeout) => (timeout, false),
                Err(error) => (0, *error.kind() == IntErrorKind::PosOverflow),
            }
        } else {
            (0, false)
        };
        let mut request = ComposeRequest {
            device: segments[0].to_string(),
            function: segments[1].to_string(),
            device_scope: device_scope.map(str::to_string),
            params: BTreeMap::new(),
            criteria: CriteriaInput::default(),
            param_sections: Vec::new(),
            criteria_sections: Vec::new(),
            timeout,
            pass_path: segments.get(5).map(ToString::to_string),
            fail_path: segments.get(6).map(ToString::to_string),
            error_code: segments.get(7).map(ToString::to_string),
        };
        let schema = match self.get_function(segments[0], segments[1], device_scope) {
            Ok(schema) => schema,
            Err(error) => {
                let function = self
                    .resolve_function(&request.device, &request.function)
                    .ok();
                diagnostics.extend(grammar::fixed_issues(
                    &request,
                    function.and_then(|function| function.convention),
                    timeout_overflowed,
                ));
                if function.and_then(grammar::profile) == Some(grammar::Encoding::Named) {
                    grammar::parse_fields(
                        &grammar::split_section_references(segments[2]).0,
                        &[],
                        grammar::Encoding::Named,
                        false,
                        &mut diagnostics,
                    );
                    if segments[3] != grammar::NULL_CRITERION && !segments[3].is_empty() {
                        grammar::parse_fields(
                            &grammar::split_section_references(segments[3]).0,
                            &[],
                            grammar::Encoding::Named,
                            true,
                            &mut diagnostics,
                        );
                    }
                }
                let (code, severity) = match &error {
                    Error::Knowledge(_) | Error::UnsupportedGrammar(_) => {
                        ("unresolved_schema", Severity::Incomplete)
                    }
                    Error::AmbiguousFunction(_) => ("ambiguous_function", Severity::Error),
                    Error::UnknownFunction { .. } => ("unknown_function", Severity::Error),
                    _ => ("invalid_input", Severity::Error),
                };
                let field = match &error {
                    Error::InvalidInput { field, .. } => field.as_str(),
                    _ => "function",
                };
                diagnostics.push(grammar::diagnostic(
                    field,
                    code,
                    error.to_string(),
                    severity,
                ));
                return Ok(validation_report(line, diagnostics));
            }
        };
        let flow_fields_omitted = schema.function.convention == Some(2) && segments.len() == 5;
        match schema.function.convention {
            Some(1) if segments.len() != 5 => diagnostics.push(grammar::diagnostic(
                "line",
                "field_count",
                "convention 1 requires exactly five fields",
                Severity::Error,
            )),
            Some(2) if flow_fields_omitted => diagnostics.push(grammar::diagnostic(
                "line",
                "field_count",
                "convention 2 requires flow fields",
                Severity::Error,
            )),
            Some(2) if matches!(segments.len(), 7 | 9) => diagnostics.push(grammar::diagnostic(
                "line",
                "historical_width",
                "historical convention-2 width accepted without changing fields",
                Severity::Warning,
            )),
            _ => {}
        }
        if let Some(encoding) = grammar::profile(&schema.function) {
            let named = encoding == grammar::Encoding::Named;
            let (parameters, param_sections) = if named {
                grammar::split_section_references(segments[2])
            } else {
                (segments[2].to_string(), Vec::new())
            };
            request.param_sections = param_sections;
            request.params = grammar::parse_fields(
                &parameters,
                &schema.parameters,
                encoding,
                false,
                &mut diagnostics,
            );
            request.criteria = if segments[3] == grammar::NULL_CRITERION || segments[3].is_empty() {
                CriteriaInput::default()
            } else if !named && schema.criteria.is_empty() {
                CriteriaInput::Raw(segments[3].to_string())
            } else {
                let (criteria, criteria_sections) = if named {
                    grammar::split_section_references(segments[3])
                } else {
                    (segments[3].to_string(), Vec::new())
                };
                request.criteria_sections = criteria_sections;
                CriteriaInput::Named(grammar::parse_fields(
                    &criteria,
                    &schema.criteria,
                    encoding,
                    true,
                    &mut diagnostics,
                ))
            };
        }
        match grammar::compose(&schema, &request, timeout_overflowed) {
            Ok(result) => diagnostics.extend(result.warnings),
            Err(Error::Validation(issues)) => {
                diagnostics.extend(issues.into_iter().filter(|issue| {
                    !(flow_fields_omitted
                        && issue.code == "required"
                        && matches!(issue.field.as_str(), "pass_path" | "fail_path"))
                }))
            }
            Err(error) => diagnostics.push(grammar::diagnostic(
                "line",
                "unsupported_grammar",
                error.to_string(),
                Severity::Incomplete,
            )),
        }
        if diagnostics
            .iter()
            .any(|issue| issue.code == "required_from_section")
        {
            diagnostics.push(grammar::diagnostic(
                "line",
                "section_reference_unresolved",
                "required values are expected from a referenced section that line tools cannot read; validate the bundle to check them",
                Severity::Incomplete,
            ));
        }
        Ok(validation_report(line, diagnostics))
    }

    pub fn suggest_criteria(
        &self,
        device: &str,
        function: &str,
        device_scope: Option<&str>,
    ) -> Result<CriteriaSuggestions> {
        let function = self.resolve_function(device, function)?;
        let scope = resolve_device_scope(function, device_scope)?;
        Ok(CriteriaSuggestions {
            criteria: self.linked_criteria(function, &scope)?,
            examples: self.function_examples(function, &scope),
        })
    }

    pub fn get_function(
        &self,
        device: &str,
        name: &str,
        device_scope: Option<&str>,
    ) -> Result<FunctionSchema> {
        let function = self.resolve_function(device, name)?;
        self.function_schema(function, device_scope)
    }

    fn function_schema(
        &self,
        function: &Function,
        device_scope: Option<&str>,
    ) -> Result<FunctionSchema> {
        let mut schema = self.linked_schema(function, device_scope)?;
        schema.examples = self.function_examples(function, &schema.device_scope);
        schema.diagnostics = grammar::support_issues(&schema);
        schema.function.composition_supported = schema.diagnostics.is_empty();
        Ok(schema)
    }

    fn function_examples(&self, function: &Function, scope: &str) -> Vec<model::Example> {
        self.snapshot
            .examples
            .iter()
            .filter(|example| {
                if example.function_source != function.source
                    || example.function_name != function.name
                {
                    return false;
                }
                if !example.device_name.is_empty()
                    && !example.device_name.eq_ignore_ascii_case(scope)
                    && !example
                        .device_name
                        .eq_ignore_ascii_case(&function.interface)
                {
                    return false;
                }
                let mut segments = example.script.split('|');
                let (Some(device), Some(name)) = (segments.next(), segments.next()) else {
                    return false;
                };
                self.resolve_function(device, name)
                    .is_ok_and(|resolved| std::ptr::eq(resolved, function))
            })
            .cloned()
            .collect()
    }

    fn linked_schema(
        &self,
        function: &Function,
        device_scope: Option<&str>,
    ) -> Result<FunctionSchema> {
        let scope = resolve_device_scope(function, device_scope)?;
        let parameters = select_fields(
            &self.snapshot.parameter_links,
            &self.snapshot.parameter_definitions,
            function,
            &scope,
        )?;
        let criteria = self.linked_criteria(function, &scope)?;
        Ok(FunctionSchema {
            function: function.clone(),
            device_scope: scope,
            parameters,
            criteria,
            examples: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn linked_criteria(&self, function: &Function, scope: &str) -> Result<Vec<Field>> {
        select_fields(
            &self.snapshot.criteria_links,
            &self.snapshot.criteria_definitions,
            function,
            scope,
        )
    }

    fn resolve_function(&self, device: &str, name: &str) -> Result<&Function> {
        let (source, interface) = device_target(device)?;
        let mut matches = self.snapshot.functions.iter().filter(|function| {
            function.source == source
                && function.interface.eq_ignore_ascii_case(interface)
                && function.name.eq_ignore_ascii_case(name)
        });
        let function = matches.next().ok_or_else(|| {
            let interfaces = self.interfaces();
            Error::UnknownFunction {
                name: format!("{device}/{name}"),
                candidates: if devices::is_known(device, &interfaces) {
                    Vec::new()
                } else {
                    devices::candidates(device, &interfaces)
                },
            }
        })?;
        if matches.next().is_some() {
            return Err(Error::AmbiguousFunction(format!("{device}/{name}")));
        }
        Ok(function)
    }

    /// Resolves a Script device, accepting an unambiguous Interface name as an alias (ADR-0009).
    pub fn resolve_device(&self, device: &str) -> Result<devices::DeviceMatch> {
        devices::resolve(device, &self.interfaces())
    }

    fn interfaces(&self) -> Vec<(String, String)> {
        devices::interfaces(&self.snapshot.functions)
    }

    pub fn list_functions(&self, device: Option<&str>) -> Result<Vec<Function>> {
        let target = device.map(device_target).transpose()?;
        let mut lookup = HashMap::with_capacity(self.snapshot.functions.len());
        for function in &self.snapshot.functions {
            lookup
                .entry(function_lookup_key(
                    &function.source,
                    &function.interface,
                    &function.name,
                ))
                .and_modify(|unique| *unique = None)
                .or_insert(Some(function));
        }
        let mut syntax = grammar::LineSyntaxCache::default();
        let mut functions: Vec<_> = self
            .snapshot
            .functions
            .iter()
            .filter(|function| {
                target.is_none_or(|(source, interface)| {
                    function.source == source && function.interface.eq_ignore_ascii_case(interface)
                })
            })
            .map(|function| {
                let mut function = function.clone();
                let device = if function.source == "DLL" {
                    format!("DLL{}", function.interface)
                } else {
                    function.interface.clone()
                };
                function.composition_supported = device_target(&device)
                    .ok()
                    .and_then(|(source, interface)| {
                        lookup
                            .get(&function_lookup_key(source, interface, &function.name))
                            .copied()
                            .flatten()
                    })
                    .filter(|resolved| grammar::profile(resolved).is_some())
                    .and_then(|resolved| self.linked_schema(resolved, None).ok())
                    .is_some_and(|schema| syntax.support_issues(&schema).is_empty());
                function
            })
            .collect();
        if let Some(device) = device
            && functions.is_empty()
        {
            return Err(devices::unknown_device(device, &self.interfaces()));
        }
        functions.sort_by(|left, right| {
            (&left.source, &left.interface, &left.name).cmp(&(
                &right.source,
                &right.interface,
                &right.name,
            ))
        });
        Ok(functions)
    }
}

fn resolve_device_scope(function: &Function, device_scope: Option<&str>) -> Result<String> {
    let scope = device_scope
        .unwrap_or(&function.interface)
        .to_ascii_uppercase();
    if scope.is_empty() || scope.trim() != scope || scope.contains(['|', '\r', '\n']) {
        return Err(Error::InvalidInput {
            field: "device_scope".into(),
            message:
                "scope must not be empty or contain surrounding whitespace, pipes, or line breaks"
                    .into(),
        });
    }
    Ok(scope)
}

fn function_lookup_key<'a>(
    source: &'a str,
    interface: &str,
    name: &str,
) -> (&'a str, String, String) {
    (
        source,
        interface.to_ascii_uppercase(),
        name.to_ascii_uppercase(),
    )
}

pub(crate) fn device_target(device: &str) -> Result<(&str, &str)> {
    if device.is_empty() || device.trim() != device || device.contains(['|', '\r', '\n']) {
        return Err(Error::InvalidInput {
            field: "device".into(),
            message: "expected a nonempty script device without surrounding whitespace or pipes"
                .into(),
        });
    }
    let (source, target) = match device.strip_prefix("DLL") {
        Some(interface) => ("DLL", interface),
        None => ("BUILT-IN", device),
    };
    let interface = if let Some((interface, mode)) = target.split_once('#') {
        if source != "DLL" || !matches!(mode, "QUICK" | "PROXY") {
            return Err(Error::InvalidInput {
                field: "device".into(),
                message: "only DLL #QUICK and #PROXY mode suffixes are supported".into(),
            });
        }
        interface
    } else {
        target
    };
    if interface.is_empty() {
        return Err(Error::InvalidInput {
            field: "device".into(),
            message: "interface is missing".into(),
        });
    }
    Ok((source, interface))
}

fn select_fields(
    links: &[Link],
    definitions: &[Definition],
    function: &Function,
    scope: &str,
) -> Result<Vec<Field>> {
    let applicable: Vec<_> = links
        .iter()
        .filter(|link| {
            link.function_source == function.source
                && link.function_name == function.name
                && (link.device_name.is_empty() || link.device_name.eq_ignore_ascii_case(scope))
        })
        .collect();
    let mut selected = BTreeMap::new();
    for link in applicable
        .iter()
        .filter(|link| link.device_name.is_empty())
        .chain(
            applicable
                .iter()
                .filter(|link| !link.device_name.is_empty()),
        )
    {
        if let Some(previous) = selected.insert(link.name.as_str(), *link)
            && previous.device_name.eq_ignore_ascii_case(&link.device_name)
        {
            return Err(Error::Knowledge(format!(
                "duplicate link for {}",
                link.name
            )));
        }
    }
    let mut fields = Vec::new();
    for link in selected.into_values() {
        let exact: Vec<_> = definitions
            .iter()
            .filter(|definition| {
                definition.name == link.name
                    && definition
                        .device_name
                        .eq_ignore_ascii_case(&link.device_name)
            })
            .collect();
        let candidates = if exact.is_empty() {
            definitions
                .iter()
                .filter(|definition| {
                    definition.name == link.name && definition.device_name.is_empty()
                })
                .collect()
        } else {
            exact
        };
        if candidates.len() > 1 {
            return Err(Error::Knowledge(format!(
                "ambiguous definition for {}",
                link.name
            )));
        }
        fields.push(Field {
            name: link.name.clone(),
            device_name: link.device_name.clone(),
            position: link.position,
            required: link.required,
            definition: candidates.first().map(|definition| (*definition).clone()),
        });
    }
    fields.sort_by(|left, right| {
        (left.position.is_none(), left.position, &left.name).cmp(&(
            right.position.is_none(),
            right.position,
            &right.name,
        ))
    });
    Ok(fields)
}

pub(crate) fn is_supported_line_width(field_count: usize) -> bool {
    matches!(field_count, 5 | 7 | 8 | 9)
}

fn validation_report(line: &str, diagnostics: Vec<Diagnostic>) -> ValidationReport {
    let status = if diagnostics
        .iter()
        .any(|issue| issue.severity == Severity::Error)
    {
        ValidationStatus::Invalid
    } else if diagnostics
        .iter()
        .any(|issue| issue.severity == Severity::Incomplete)
    {
        ValidationStatus::Incomplete
    } else {
        ValidationStatus::Valid
    };
    ValidationReport {
        status,
        segments: line.split('|').map(str::to_string).collect(),
        diagnostics,
    }
}
