pub mod bundle;
mod grammar;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod model;
#[cfg(feature = "database")]
pub mod postgres;
#[cfg(feature = "legacy-sqlite")]
pub mod sqlite;

use std::collections::BTreeMap;

use model::{
    ComposeRequest, ComposeResult, CriteriaInput, CriteriaSuggestions, Definition, Diagnostic,
    Field, Function, FunctionSchema, Link, Severity, Snapshot, ValidationReport, ValidationStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown function: {0}")]
    UnknownFunction(String),
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
            Self::UnknownFunction(_) => "unknown_function",
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
}

pub type Result<Value> = std::result::Result<Value, Error>;

pub trait Catalog: Send + Sync {
    fn snapshot(&self) -> Result<Snapshot>;
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
        grammar::compose(&schema, &request)
    }

    pub fn validate_line(
        &self,
        line: &str,
        device_scope: Option<&str>,
    ) -> Result<ValidationReport> {
        let segments: Vec<String> = line.split('|').map(str::to_string).collect();
        let mut diagnostics = Vec::new();
        if line.contains(['\r', '\n']) {
            diagnostics.push(grammar::diagnostic(
                "line",
                "reserved_character",
                "a line must not contain line breaks",
                Severity::Error,
            ));
        }
        if !matches!(segments.len(), 5 | 7 | 8 | 9) {
            diagnostics.push(grammar::diagnostic(
                "line",
                "field_count",
                "expected 5, 7, 8, or 9 pipe-delimited fields",
                Severity::Error,
            ));
            return Ok(validation_report(segments, diagnostics));
        }
        let timeout = if !segments[4].is_empty()
            && segments[4]
                .bytes()
                .all(|character| character.is_ascii_digit())
        {
            segments[4].parse::<u64>().unwrap_or(0)
        } else {
            0
        };
        let mut request = ComposeRequest {
            device: segments[0].clone(),
            function: segments[1].clone(),
            device_scope: device_scope.map(str::to_string),
            params: BTreeMap::new(),
            criteria: CriteriaInput::default(),
            timeout,
            pass_path: segments.get(5).cloned(),
            fail_path: segments.get(6).cloned(),
            error_code: segments.get(7).cloned(),
        };
        let schema = match self.get_function(&segments[0], &segments[1], device_scope) {
            Ok(schema) => schema,
            Err(error) => {
                let function = self
                    .resolve_function(&request.device, &request.function)
                    .ok();
                diagnostics.extend(grammar::fixed_issues(
                    &request,
                    function.and_then(|function| function.convention),
                ));
                if function.and_then(grammar::profile) == Some(grammar::Encoding::Named) {
                    grammar::parse_fields(
                        &segments[2],
                        &[],
                        grammar::Encoding::Named,
                        false,
                        &mut diagnostics,
                    );
                    if segments[3] != "NULL" && !segments[3].is_empty() {
                        grammar::parse_fields(
                            &segments[3],
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
                    Error::UnknownFunction(_) => ("unknown_function", Severity::Error),
                    _ => ("invalid_input", Severity::Error),
                };
                diagnostics.push(grammar::diagnostic(
                    "function",
                    code,
                    error.to_string(),
                    severity,
                ));
                return Ok(validation_report(segments, diagnostics));
            }
        };
        match schema.function.convention {
            Some(1) if segments.len() != 5 => diagnostics.push(grammar::diagnostic(
                "line",
                "field_count",
                "convention 1 requires exactly five fields",
                Severity::Error,
            )),
            Some(2) if segments.len() == 5 => diagnostics.push(grammar::diagnostic(
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
            request.params = grammar::parse_fields(
                &segments[2],
                &schema.parameters,
                encoding,
                false,
                &mut diagnostics,
            );
            request.criteria = if segments[3] == "NULL" || segments[3].is_empty() {
                CriteriaInput::default()
            } else if encoding == grammar::Encoding::Raw {
                CriteriaInput::Raw(segments[3].clone())
            } else {
                CriteriaInput::Named(grammar::parse_fields(
                    &segments[3],
                    &schema.criteria,
                    encoding,
                    true,
                    &mut diagnostics,
                ))
            };
        }
        match grammar::compose(&schema, &request) {
            Ok(result) => diagnostics.extend(result.warnings),
            Err(Error::Validation(issues)) => diagnostics.extend(issues),
            Err(error) => diagnostics.push(grammar::diagnostic(
                "line",
                "unsupported_grammar",
                error.to_string(),
                Severity::Incomplete,
            )),
        }
        Ok(validation_report(segments, diagnostics))
    }

    pub fn suggest_criteria(
        &self,
        device: &str,
        function: &str,
        device_scope: Option<&str>,
    ) -> Result<CriteriaSuggestions> {
        let schema = self.get_function(device, function, device_scope)?;
        Ok(CriteriaSuggestions {
            criteria: schema.criteria,
            examples: schema.examples,
        })
    }

    pub fn get_function(
        &self,
        device: &str,
        name: &str,
        device_scope: Option<&str>,
    ) -> Result<FunctionSchema> {
        let function = self.resolve_function(device, name)?;
        let scope = device_scope
            .unwrap_or(&function.interface)
            .to_ascii_uppercase();
        if scope.trim() != scope || scope.contains(['|', '\r', '\n']) {
            return Err(Error::InvalidInput {
                field: "device_scope".into(),
                message: "scope must not contain surrounding whitespace, pipes, or line breaks"
                    .into(),
            });
        }
        let parameters = select_fields(
            &self.snapshot.parameter_links,
            &self.snapshot.parameter_definitions,
            function,
            &scope,
        )?;
        let criteria = select_fields(
            &self.snapshot.criteria_links,
            &self.snapshot.criteria_definitions,
            function,
            &scope,
        )?;
        let examples = self
            .snapshot
            .examples
            .iter()
            .filter(|example| {
                if example.function_source != function.source
                    || example.function_name != function.name
                {
                    return false;
                }
                if !example.device_name.is_empty()
                    && !example.device_name.eq_ignore_ascii_case(&scope)
                    && !example
                        .device_name
                        .eq_ignore_ascii_case(&function.interface)
                {
                    return false;
                }
                let mut segments = example.script.split('|');
                segments
                    .next()
                    .and_then(|token| device_target(token).ok())
                    .is_some_and(|(source, interface)| {
                        source == function.source
                            && interface.eq_ignore_ascii_case(&function.interface)
                    })
                    && segments.next() == Some(function.name.as_str())
            })
            .cloned()
            .collect();
        let mut schema = FunctionSchema {
            function: function.clone(),
            device_scope: scope,
            parameters,
            criteria,
            examples,
            diagnostics: Vec::new(),
        };
        schema.diagnostics = grammar::support_issues(&schema);
        schema.function.composition_supported = schema.diagnostics.is_empty();
        Ok(schema)
    }

    fn resolve_function(&self, device: &str, name: &str) -> Result<&Function> {
        let (source, interface) = device_target(device)?;
        let mut matches = self.snapshot.functions.iter().filter(|function| {
            function.source == source
                && function.interface.eq_ignore_ascii_case(interface)
                && function.name.eq_ignore_ascii_case(name)
        });
        let function = matches
            .next()
            .ok_or_else(|| Error::UnknownFunction(format!("{device}/{name}")))?;
        if matches.next().is_some() {
            return Err(Error::AmbiguousFunction(format!("{device}/{name}")));
        }
        Ok(function)
    }

    pub fn list_functions(&self, device: Option<&str>) -> Result<Vec<Function>> {
        let target = device.map(device_target).transpose()?;
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
                function.composition_supported = self
                    .get_function(&device, &function.name, None)
                    .is_ok_and(|schema| schema.function.composition_supported);
                function
            })
            .collect();
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

fn device_target(device: &str) -> Result<(&str, &str)> {
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

fn validation_report(segments: Vec<String>, diagnostics: Vec<Diagnostic>) -> ValidationReport {
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
        segments,
        diagnostics,
    }
}
