use std::sync::Arc;

use rmcp::{
    ErrorData, ServerHandler, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    Catalog, Engine, Error, Result as EngineResult,
    devices::{DeviceMatch, MatchedBy},
    model::{ComposeRequest, Snapshot},
};

#[derive(Clone)]
pub struct McpServer {
    catalog: Arc<dyn Catalog>,
}

/// Sent in `initialize` so clients learn the domain vocabulary and tool order up front.
pub const INSTRUCTIONS: &str = "Read-only knowledge of test-script Functions; composes and validates Script lines and INI bundles without executing anything.

Vocabulary:
- Script device: the first field of a Script line, e.g. `SSH` or `DLLWIFI_TEST`. DLL Functions take a `DLL` prefix; an optional `#MODE` suffix (e.g. `DLLQSPR#QUICK`) selects an execution mode. Discovery tools also accept a bare Interface name as an alias.
- Device scope: the Device name on definitions, links, and Examples; blank means Global. A scoped definition overrides the Global one. It is not the Script device.
- Script line: `device|function|params|criteria|timeout` (convention 1) or with `|pass|fail|error_code` flow fields (convention 2). Use `NULL` for no criteria.

Recommended order:
1. `catalog_info` for the contract and cache revision; `list_devices` and `get_device` to find a Script device.
2. `list_functions`, `search_catalog`, or `get_function_readiness` to choose a ready Function.
3. `get_function` (or `list_function_fields`, `get_definition`) for parameters, criteria, and Examples; `suggest_criteria` and `list_examples` for patterns.
4. `compose_line` to build a line, then `validate_line` or `parse_line` to check one. For INI files use `validate_ini_bundle`, `compose_ini_bundle`, and `compare_plan_to_bundle`.

Resources: read `docs://script-grammar`, `docs://script-devices`, and `docs://ini-bundle-dialects` for the line and bundle rules. `catalog://` resources (see resources/templates/list) return the same JSON as the matching discovery tools.

Prompts: `compose-test-step`, `explain-script-line`, `review-ini-bundle`, `plan-to-bundle`, `audit-function-readiness`, and `troubleshoot-failing-line` script these workflows step by step.

Errors return `isError: true` with a structured `error.code` (e.g. `unknown_device` with `candidates`); correct the input and retry.";

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(
            rmcp::model::Implementation::new("Script Audit", env!("CARGO_PKG_VERSION")).with_icons(
                vec![
                    rmcp::model::Icon::new(include_str!("../resources/server-icon.data-uri"))
                        .with_mime_type("image/png")
                        .with_sizes(vec!["480x480".into()]),
                ],
            ),
        )
        .with_instructions(INSTRUCTIONS.to_string())
    }

    async fn list_resources(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListResourcesResult, ErrorData> {
        Ok(
            rmcp::model::ListResourcesResult::with_all_items(resources::list())
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn list_resource_templates(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListResourceTemplatesResult, ErrorData> {
        Ok(
            rmcp::model::ListResourceTemplatesResult::with_all_items(resources::templates())
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ReadResourceResponse, ErrorData> {
        resources::read(self, &request.uri).await.map(|result| {
            result
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private)
                .into()
        })
    }

    async fn list_prompts(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListPromptsResult, ErrorData> {
        Ok(
            rmcp::model::ListPromptsResult::with_all_items(prompts::list())
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::GetPromptResponse, ErrorData> {
        prompts::get(&request.name, request.arguments).map(Into::into)
    }
}

mod prompts;
mod resources;

pub use crate::discovery::FunctionQuery as ListFunctionsRequest;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListFunctionFieldsRequest {
    /// Script device token; an Interface name is accepted as an alias.
    pub device: String,
    /// One Function name; omit to list every Function on the device.
    pub function: Option<String>,
    pub device_scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefinitionRequest {
    /// `parameter` or `criterion`.
    pub kind: crate::discovery::FieldKind,
    /// Field name, matched case-insensitively.
    pub name: String,
    /// Device scope; omit to include every scoped variant.
    pub device_scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetDeviceRequest {
    /// Script device token, e.g. `SSH` or `DLLWIFI_TEST`; an Interface name is accepted as an alias.
    pub device: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetFunctionRequest {
    pub device: String,
    pub name: String,
    pub device_scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuggestCriteriaRequest {
    pub device: String,
    pub function: String,
    pub device_scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateLineRequest {
    pub line: String,
    pub device_scope: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct DeviceList {
    pub devices: Vec<crate::discovery::DeviceRow>,
}

/// Body of an `isError: true` tool result.
#[derive(Serialize, JsonSchema)]
pub struct ToolErrorBody {
    /// Stable error code, e.g. `unknown_device`, `unknown_function`, `invalid_input`.
    pub code: String,
    pub message: String,
    pub diagnostics: Vec<crate::model::Diagnostic>,
    /// Close matches when a Script device or Function is unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct ToolError {
    pub error: ToolErrorBody,
}

/// A Script device result plus the match fields `invoke_device` adds when a device resolves.
#[derive(Serialize, JsonSchema)]
#[allow(dead_code, reason = "schema-only type")]
struct Matched<T> {
    #[serde(flatten)]
    result: T,
    /// The Script device the request resolved to.
    #[serde(skip_serializing_if = "Option::is_none")]
    script_device: Option<String>,
    /// `script_device` for an exact match, `interface` for an Interface alias (ADR 0009).
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_by: Option<MatchedBy>,
}

#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code, reason = "schema-only type")]
enum ToolOutput<T> {
    Success(T),
    Error(ToolError),
}

/// Output schema accepting a `T` result or the shared error envelope. It uses the serialize
/// contract so `skip_serializing_if` fields are optional, and MCP requires an object root, so
/// the `anyOf` sits under `type: "object"`.
fn output_schema<T: JsonSchema + 'static>() -> Arc<rmcp::model::JsonObject> {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.contract = schemars::generate::Contract::Serialize;
    let root = settings
        .into_generator()
        .into_root_schema_for::<ToolOutput<T>>();
    let mut schema = match serde_json::to_value(root) {
        Ok(serde_json::Value::Object(schema)) => schema,
        _ => rmcp::model::JsonObject::new(),
    };
    schema.remove("title");
    schema.remove("description");
    schema.insert("type".into(), serde_json::json!("object"));
    Arc::new(schema)
}

/// [`output_schema`] for tools whose results carry `script_device` and `matched_by`.
fn device_output_schema<T: JsonSchema + 'static>() -> Arc<rmcp::model::JsonObject> {
    output_schema::<Matched<T>>()
}

#[tool_router(vis = "pub")]
impl McpServer {
    pub fn new(catalog: Arc<dyn Catalog>) -> Self {
        Self { catalog }
    }

    #[tool(
        title = "List Functions",
        output_schema = device_output_schema::<crate::discovery::FunctionPage>(),
        description = "List catalog Functions with Script device, readiness (ready, bundle_ready, not_ready), conventions, categories, and composition support. Optional AND filters: device (a Script device token, not a Device scope), category, execution_phase, composable_only. Page with limit and the returned next_cursor; select row keys with fields.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_functions(
        &self,
        Parameters(query): Parameters<ListFunctionsRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let preflight = ListFunctionsRequest {
            device: None,
            ..query.clone()
        };
        if let Err(error) = Engine::new(Snapshot::default()).list_function_rows(&preflight) {
            return Ok(domain_error(error));
        }
        match query.device.clone() {
            Some(device) => {
                self.invoke_device(
                    device,
                    Alias::Accept,
                    |catalog, device| catalog.device_snapshot(device),
                    move |engine, device| {
                        engine.list_function_rows(&ListFunctionsRequest {
                            device: Some(device.into()),
                            ..query
                        })
                    },
                )
                .await
            }
            None => {
                self.invoke_on(
                    |catalog| catalog.snapshot_without_examples(),
                    move |engine| engine.list_function_rows(&query),
                )
                .await
            }
        }
    }

    #[tool(
        title = "Get Function",
        output_schema = device_output_schema::<crate::model::FunctionSchema>(),
        description = "Read full scoped parameter and criteria definitions, patterns, defaults, required flags, and stored examples. No defaults are applied.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_function(
        &self,
        Parameters(request): Parameters<GetFunctionRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let name = request.name.clone();
        self.invoke_device(
            request.device,
            Alias::Accept,
            move |catalog, device| catalog.function_snapshot(device, &name),
            move |engine, device| {
                engine.get_function(device, &request.name, request.device_scope.as_deref())
            },
        )
        .await
    }

    #[tool(
        title = "List Script Devices",
        output_schema = output_schema::<DeviceList>(),
        description = "List reachable Script devices (the first line field), their source, Interface, accepted DLL mode suffixes, and Function and composable counts. Start here to find a device token.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_devices(&self) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            |engine| Ok(serde_json::json!({"devices": engine.list_devices()?})),
        )
        .await
    }

    #[tool(
        title = "List Function Fields",
        output_schema = device_output_schema::<crate::discovery::FunctionFieldsList>(),
        description = "List resolved parameters and criteria (link plus scoped-over-Global definition, as in get_function) for one Function or, without function, every Function on a Script device. No Examples.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_function_fields(
        &self,
        Parameters(request): Parameters<ListFunctionFieldsRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let function = request.function.clone();
        self.invoke_device(
            request.device,
            Alias::Accept,
            move |catalog, device| match &function {
                Some(name) => catalog.function_snapshot_without_examples(device, name),
                None => catalog.device_snapshot(device),
            },
            move |engine, device| {
                engine.list_function_fields(
                    device,
                    request.function.as_deref(),
                    request.device_scope.as_deref(),
                )
            },
        )
        .await
    }

    #[tool(
        title = "Get Definition",
        output_schema = output_schema::<crate::discovery::DefinitionLookup>(),
        description = "Read the Global and scoped parameter or criterion definitions with a name (case-insensitive), each labelled global or scoped. A device_scope keeps Global plus that scope. Unknown names return an empty list.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_definition(
        &self,
        Parameters(request): Parameters<DefinitionRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            move |engine| {
                engine.get_definition(request.kind, &request.name, request.device_scope.as_deref())
            },
        )
        .await
    }

    #[tool(
        title = "Find Functions Using a Field",
        output_schema = output_schema::<crate::discovery::FieldUsers>(),
        description = "Find the Functions whose applicable links reference a parameter or criterion, each once, with Script device, link scope, position, and required flag. Unknown names return an empty list.",
        annotations(read_only_hint = true)
    )]
    pub async fn find_functions_using(
        &self,
        Parameters(request): Parameters<DefinitionRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            move |engine| {
                engine.find_functions_using(
                    request.kind,
                    &request.name,
                    request.device_scope.as_deref(),
                )
            },
        )
        .await
    }

    #[tool(
        title = "Catalog Info",
        output_schema = output_schema::<crate::discovery::CatalogInfo>(),
        description = "Report the catalog contract (mcp_v1 or legacy), a sha256 content-hash revision for caching, the server version, and row counts for Functions, Script devices, definitions, links, Examples, audited grammars, and key audits. Reads the full catalog.",
        annotations(read_only_hint = true)
    )]
    pub async fn catalog_info(&self) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(|engine| engine.catalog_info()).await
    }

    #[tool(
        title = "Search Catalog",
        output_schema = output_schema::<crate::discovery::SearchResults>(),
        description = "Search Function, parameter, and criterion names and descriptions (case-insensitive; every term must match). Name matches rank above description matches. Optional kinds filter; limit 1-100 (default 20).",
        annotations(read_only_hint = true)
    )]
    pub async fn search_catalog(
        &self,
        Parameters(query): Parameters<crate::discovery::SearchQuery>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if query.query.trim().is_empty() {
            return Ok(domain_error(Error::InvalidInput {
                field: "query".into(),
                message: "must contain at least one search term".into(),
            }));
        }
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            move |engine| engine.search_catalog(&query),
        )
        .await
    }

    #[tool(
        title = "List Examples",
        output_schema = device_output_schema::<crate::discovery::ExamplePage>(),
        description = "List stored Examples (script and meaning), filtered by Script device, Function, and case-insensitive text over script or meaning. Pages with limit (default 50) and the returned next_cursor.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_examples(
        &self,
        Parameters(query): Parameters<crate::discovery::ExampleQuery>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let preflight = crate::discovery::ExampleQuery {
            device: None,
            function: None,
            ..query.clone()
        };
        if let Err(error) = Engine::new(Snapshot::default()).list_examples(&preflight) {
            return Ok(domain_error(error));
        }
        match query.device.clone() {
            Some(device) => {
                self.invoke_device(
                    device,
                    Alias::Accept,
                    |catalog, _| catalog.snapshot(),
                    move |engine, device| {
                        engine.list_examples(&crate::discovery::ExampleQuery {
                            device: Some(device.into()),
                            ..query
                        })
                    },
                )
                .await
            }
            None => {
                self.invoke(move |engine| engine.list_examples(&query))
                    .await
            }
        }
    }

    #[tool(
        title = "Get Script Device",
        output_schema = device_output_schema::<crate::discovery::DeviceSummary>(),
        description = "Summarize one Script device: its list_devices row, Function readiness counts, and linked parameter and criteria names with whether a scoped or Global definition resolves.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_device(
        &self,
        Parameters(request): Parameters<GetDeviceRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_device(
            request.device,
            Alias::Accept,
            |catalog, device| catalog.device_snapshot(device),
            |engine, device| engine.get_device(device),
        )
        .await
    }

    #[tool(
        title = "Get Function Readiness",
        output_schema = device_output_schema::<crate::discovery::FunctionReadiness>(),
        description = "Explain whether a Function is ready (lines and bundles), bundle_ready (INI bundles only), or not_ready, with line and bundle issues, grammar profile, linked fields, and unaudited script keys.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_function_readiness(
        &self,
        Parameters(request): Parameters<GetFunctionRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let name = request.name.clone();
        self.invoke_device(
            request.device,
            Alias::Accept,
            move |catalog, device| catalog.function_snapshot_without_examples(device, &name),
            move |engine, device| {
                engine.function_readiness(device, &request.name, request.device_scope.as_deref())
            },
        )
        .await
    }

    #[tool(
        title = "Suggest Criteria",
        output_schema = device_output_schema::<crate::model::CriteriaSuggestions>(),
        description = "Read known criteria definitions and recorded usage examples without inventing thresholds.",
        annotations(read_only_hint = true)
    )]
    pub async fn suggest_criteria(
        &self,
        Parameters(request): Parameters<SuggestCriteriaRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let name = request.function.clone();
        self.invoke_device(
            request.device,
            Alias::Accept,
            move |catalog, device| catalog.function_snapshot(device, &name),
            move |engine, device| {
                engine.suggest_criteria(device, &request.function, request.device_scope.as_deref())
            },
        )
        .await
    }

    #[tool(
        title = "Compose Script Line",
        output_schema = output_schema::<crate::model::ComposeResult>(),
        description = "Compose a validated five/eight-field script line using an audited profile. SINGLE values are strings and MULTIPLE values are string arrays. This tool never executes scripts.",
        annotations(read_only_hint = true)
    )]
    pub async fn compose_line(
        &self,
        Parameters(request): Parameters<ComposeRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let name = request.function.clone();
        self.invoke_device(
            request.device.clone(),
            Alias::Reject,
            move |catalog, device| catalog.function_snapshot_without_examples(device, &name),
            move |engine, _| engine.compose_line(request),
        )
        .await
    }

    #[tool(
        title = "Validate Script Line",
        output_schema = output_schema::<crate::model::ValidationReport>(),
        description = "Check a script line against scoped knowledge. Report valid, invalid, or incomplete and preserve original fields; historical seven/nine-field lines warn. Runtime references are never resolved.",
        annotations(read_only_hint = true)
    )]
    pub async fn validate_line(
        &self,
        Parameters(request): Parameters<ValidateLineRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut fields = request.line.split('|');
        let target = (!crate::is_commented_line(&request.line)
            && crate::is_supported_line_width(fields.clone().count()))
        .then(|| {
            let device = fields.next().unwrap_or_default().to_string();
            let name = fields.next().unwrap_or_default().to_string();
            (device, name)
        });
        let validate = move |engine: Engine| {
            engine.validate_line(&request.line, request.device_scope.as_deref())
        };
        if let Some((device, name)) = target {
            self.invoke_function_with(
                device,
                name,
                |catalog, device, name| catalog.function_snapshot_without_examples(device, name),
                validate,
            )
            .await
        } else {
            self.invoke_on(|_| Ok(Snapshot::default()), validate).await
        }
    }

    #[tool(
        title = "Parse Script Line",
        output_schema = output_schema::<crate::discovery::ParsedLine>(),
        description = "Split a Script line into Script device, Function, parameters, criteria, timeout, and flow fields; annotate each parameter and criterion with its resolved definition (scoped, global, or missing). Raw payloads and *V:Section# references are labelled. Includes validate_line diagnostics.",
        annotations(read_only_hint = true)
    )]
    pub async fn parse_line(
        &self,
        Parameters(request): Parameters<ValidateLineRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut fields = request.line.split('|');
        let device = fields.next().unwrap_or_default().to_string();
        let name = fields.next().unwrap_or_default().to_string();
        let parse =
            move |engine: Engine| engine.parse_line(&request.line, request.device_scope.as_deref());
        if name.is_empty() {
            self.invoke_on(|_| Ok(Snapshot::default()), parse).await
        } else {
            self.invoke_function_with(
                device,
                name,
                |catalog, device, name| catalog.function_snapshot_without_examples(device, name),
                parse,
            )
            .await
        }
    }

    #[tool(
        title = "Validate INI Bundle",
        output_schema = output_schema::<rmcp::model::JsonObject>(),
        description = "Validate supplied INI bundle text with an explicit dialect and TEST FLOW. Preserves source, reports structural and local branch defects, and identifies incomplete semantic checks. No execution or filesystem access.",
        annotations(read_only_hint = true)
    )]
    pub async fn validate_ini_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::ValidateBundleRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let request = match request.prepare() {
            Ok(request) => request,
            Err(error) => return Ok(domain_error(error)),
        };
        self.invoke_catalog(move |catalog| {
            request.validate(|| catalog.snapshot_without_examples().map(Engine::new))
        })
        .await
    }

    #[tool(
        title = "Compare Test Plan to Bundle",
        output_schema = output_schema::<rmcp::model::JsonObject>(),
        description = "Compare reviewed sourced requirements with reachable supplied INI behavior. Reports coverage and unresolved conflicts, never certifies document interpretation or hardware execution. No filesystem writes.",
        annotations(read_only_hint = true)
    )]
    pub async fn compare_plan_to_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::plan::ComparePlanRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let request = match request.prepare() {
            Ok(request) => request,
            Err(error) => return Ok(domain_error(error)),
        };
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            move |engine| request.compare(&engine),
        )
        .await
    }

    #[tool(
        title = "Compose INI Bundle",
        output_schema = output_schema::<rmcp::model::JsonObject>(),
        description = "Compose a read-only reviewed-base INI draft from sourced requirements and approved templates. Returns exact draft/input identities, draft contents, diffs, validation, coverage, blockers and optional unauthenticated approval-claim metadata. Client human approval is required before client export; never writes, executes or packages scripts.",
        annotations(read_only_hint = true)
    )]
    pub async fn compose_ini_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::compose::ComposeBundleRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let request = match request.prepare() {
            Ok(request) => request,
            Err(error) => return Ok(domain_error(error)),
        };
        self.invoke(move |engine| request.compose(&engine)).await
    }
}

impl McpServer {
    async fn invoke<Output: Serialize + Send + 'static>(
        &self,
        operation: impl FnOnce(Engine) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_on(|catalog| catalog.snapshot(), operation)
            .await
    }

    /// Runs a Script device operation. Interface names resolve as aliases (ADR-0009) only after
    /// the exact scoped read misses; misses carry suggested Script devices.
    async fn invoke_device<Output: Serialize + Send + 'static>(
        &self,
        device: String,
        alias: Alias,
        load: impl Fn(&dyn Catalog, &str) -> EngineResult<Snapshot> + Send + 'static,
        operation: impl FnOnce(Engine, &str) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_catalog(move |catalog| {
            let Ok((source, interface)) = crate::device_target(&device) else {
                // Keep the Engine's input error without touching the catalog.
                return operation(Engine::new(Snapshot::default()), &device).and_then(plain);
            };
            let snapshot = load(catalog, &device)?;
            let exact = snapshot.functions.iter().any(|function| {
                function.source == source && function.interface.eq_ignore_ascii_case(interface)
            });
            let matched = if exact {
                DeviceMatch {
                    script_device: device.clone(),
                    matched_by: MatchedBy::ScriptDevice,
                }
            } else {
                match crate::devices::resolve(&device, &catalog.interfaces()?) {
                    Ok(matched) if matched.matched_by == MatchedBy::ScriptDevice => matched,
                    Ok(matched) if alias == Alias::Accept => {
                        let snapshot = load(catalog, &matched.script_device)?;
                        let output = operation(Engine::new(snapshot), &matched.script_device)?;
                        return annotated(output, &matched);
                    }
                    Ok(matched) => {
                        return operation(Engine::new(snapshot), &device)
                            .map_err(|error| error.with_candidates(vec![matched.script_device]))
                            .and_then(plain);
                    }
                    Err(unknown) => {
                        return operation(Engine::new(snapshot), &device)
                            .map_err(|error| error.with_candidates(unknown.candidates().to_vec()))
                            .and_then(plain);
                    }
                }
            };
            let output = operation(Engine::new(snapshot), &device)?;
            match alias {
                Alias::Accept => annotated(output, &matched),
                Alias::Reject => plain(output),
            }
        })
        .await
    }

    async fn invoke_function_with<Output: Serialize + Send + 'static>(
        &self,
        device: String,
        name: String,
        load: fn(&dyn Catalog, &str, &str) -> EngineResult<Snapshot>,
        operation: impl FnOnce(Engine) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_on(
            move |catalog| {
                if crate::device_target(&device).is_err() {
                    // Keep the Engine's response, including validate_line's diagnostic report.
                    return Ok(Snapshot::default());
                }
                load(catalog, &device, &name)
            },
            operation,
        )
        .await
    }

    async fn invoke_on<Output: Serialize + Send + 'static>(
        &self,
        load: impl FnOnce(&dyn Catalog) -> EngineResult<Snapshot> + Send + 'static,
        operation: impl FnOnce(Engine) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_catalog(move |catalog| operation(Engine::new(load(catalog)?)))
            .await
    }

    async fn invoke_catalog<Output: Serialize + Send + 'static>(
        &self,
        operation: impl FnOnce(&dyn Catalog) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let catalog = Arc::clone(&self.catalog);
        let outcome = tokio::task::spawn_blocking(move || operation(catalog.as_ref()))
            .await
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        match outcome {
            Ok(output) => serde_json::to_value(output)
                .map(CallToolResult::structured)
                .map_err(|error| ErrorData::internal_error(error.to_string(), None)),
            Err(error) => Ok(domain_error(error)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alias {
    /// Catalog reads accept an Interface name for its only Script device.
    Accept,
    /// Lines dispatch on the literal Script device, so aliases only become suggestions.
    Reject,
}

fn plain(output: impl Serialize) -> EngineResult<serde_json::Value> {
    serde_json::to_value(output).map_err(|error| Error::Knowledge(error.to_string()))
}

fn annotated(output: impl Serialize, matched: &DeviceMatch) -> EngineResult<serde_json::Value> {
    let mut value = plain(output)?;
    if let Some(fields) = value.as_object_mut() {
        fields.insert("script_device".into(), matched.script_device.clone().into());
        fields.insert("matched_by".into(), plain(matched.matched_by)?);
    }
    Ok(value)
}

fn domain_error(error: Error) -> CallToolResult {
    let diagnostics = match &error {
        Error::Validation(issues) => issues.as_slice(),
        _ => &[],
    };
    let mut body = serde_json::json!({
        "code": error.code(), "message": error.to_string(), "diagnostics": diagnostics
    });
    if !error.candidates().is_empty() {
        body["candidates"] = serde_json::json!(error.candidates());
    }
    CallToolResult::structured_error(serde_json::json!({ "error": body }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct UnavailableCatalog;

    impl Catalog for UnavailableCatalog {
        fn snapshot(&self) -> EngineResult<Snapshot> {
            Err(Error::Knowledge("catalog must not be loaded".into()))
        }
    }

    #[tokio::test]
    async fn bundle_preflight_errors_skip_catalog()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let server = McpServer::new(Arc::new(UnavailableCatalog));
        let bundle = json!({"files": [], "selected_flow": "", "dialect": "hh5k"});
        let comparison = json!({
            "bundle": bundle,
            "plan": {
                "controlling_source": "fixture", "station": "Normal", "requirements": [],
                "sources": [{"id": "", "revision": "1", "kind": "test_plan", "approved": false}]
            },
            "flow_variant": "normal"
        });
        let composition = json!({"comparison": comparison, "flow_anchor": "x".repeat(513)});
        let results = [
            server
                .validate_ini_bundle(Parameters(serde_json::from_value(bundle)?))
                .await?,
            server
                .compare_plan_to_bundle(Parameters(serde_json::from_value(comparison)?))
                .await?,
            server
                .compose_ini_bundle(Parameters(serde_json::from_value(composition)?))
                .await?,
        ];
        let expected = Some(json!({"error": {
            "code": "invalid_input",
            "message": "invalid bundle: supply between 1 and 16 logical files",
            "diagnostics": []
        }}));
        for result in results {
            assert_eq!(result.is_error, Some(true));
            assert_eq!(result.structured_content, expected);
        }
        Ok(())
    }

    #[tokio::test]
    async fn missing_main_flow_skips_catalog() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let server = McpServer::new(Arc::new(UnavailableCatalog));
        let bundle = json!({
            "files": [{"name": "TEST_SPEC.ini", "text": "[SPEC]\nA=1\n"}],
            "selected_flow": "[TEST FLOW:Normal]",
            "dialect": "hh5k"
        });
        let plan = json!({
            "controlling_source": "fixture", "station": "Normal", "requirements": [],
            "sources": [{"id": "fixture", "revision": "1", "kind": "test_plan", "approved": true}]
        });
        let comparison = json!({"bundle": bundle, "plan": plan, "flow_variant": "normal"});
        let composition = json!({"comparison": comparison, "flow_anchor": "; anchor\n"});
        let results = [
            server
                .validate_ini_bundle(Parameters(serde_json::from_value(bundle.clone())?))
                .await?,
            server
                .compare_plan_to_bundle(Parameters(serde_json::from_value(comparison.clone())?))
                .await?,
            server
                .compose_ini_bundle(Parameters(serde_json::from_value(composition)?))
                .await?,
        ];
        let expected = Some(json!({"error": {
            "code": "invalid_input",
            "message": "invalid bundle: MAIN_FLOW.ini is required to select a flow",
            "diagnostics": []
        }}));
        for result in results {
            assert_eq!(result.is_error, Some(true));
            assert_eq!(result.structured_content, expected);
        }

        let mut duplicate_sources = comparison;
        duplicate_sources["plan"]["sources"][0]["id"] = json!("");
        let result = server
            .compare_plan_to_bundle(Parameters(serde_json::from_value(duplicate_sources)?))
            .await?;
        assert_eq!(
            result.structured_content,
            Some(json!({"error": {
                "code": "invalid_input",
                "message": "invalid bundle: source IDs must be nonempty and unique",
                "diagnostics": []
            }}))
        );
        Ok(())
    }

    #[tokio::test]
    async fn wrong_width_validate_line_skips_catalog() -> std::result::Result<(), ErrorData> {
        let server = McpServer::new(Arc::new(UnavailableCatalog));
        let result = server
            .validate_line(Parameters(ValidateLineRequest {
                line: "SSH|OPEN|DUT@echo|NULL|1|".into(),
                device_scope: None,
            }))
            .await?;
        assert_eq!(
            result.structured_content,
            Some(json!({
                "status": "invalid",
                "segments": ["SSH", "OPEN", "DUT@echo", "NULL", "1", ""],
                "diagnostics": [{
                    "field": "line",
                    "code": "field_count",
                    "message": "expected 5, 7, 8, or 9 pipe-delimited fields",
                    "severity": "error"
                }]
            }))
        );
        assert_ne!(result.is_error, Some(true));
        Ok(())
    }

    #[tokio::test]
    async fn commented_validate_line_skips_catalog() -> std::result::Result<(), ErrorData> {
        let server = McpServer::new(Arc::new(UnavailableCatalog));
        for line in [
            ";SSH|OPEN|dut@hello|NULL|500",
            "  //SSH|OPEN|dut@hello|NULL|500",
        ] {
            let result = server
                .validate_line(Parameters(ValidateLineRequest {
                    line: line.into(),
                    device_scope: None,
                }))
                .await?;
            assert_eq!(
                result.structured_content,
                Some(json!({
                    "status": "invalid",
                    "segments": line.split('|').collect::<Vec<_>>(),
                    "diagnostics": [{
                        "field": "line",
                        "code": "commented_line",
                        "message": "line is commented out with ';' or '//' and the tester skips it; remove the comment prefix to validate the row",
                        "severity": "error"
                    }]
                })),
                "{line}"
            );
            assert_ne!(result.is_error, Some(true));
        }
        Ok(())
    }

    #[tokio::test]
    async fn list_functions_uses_device_snapshot_only_with_a_filter()
    -> std::result::Result<(), ErrorData> {
        struct ScopedCatalog;

        impl Catalog for ScopedCatalog {
            fn snapshot(&self) -> EngineResult<Snapshot> {
                Ok(Snapshot::default())
            }

            fn device_snapshot(&self, device: &str) -> EngineResult<Snapshot> {
                assert_eq!(device, "ssh");
                Err(Error::Knowledge("scoped catalog was loaded".into()))
            }
        }

        let server = McpServer::new(Arc::new(ScopedCatalog));
        let broad = server
            .list_functions(Parameters(ListFunctionsRequest::default()))
            .await?;
        assert_eq!(broad.structured_content, Some(json!({"functions": []})));
        let invalid = server
            .list_functions(Parameters(ListFunctionsRequest {
                device: Some("ssh".into()),
                limit: Some(0),
                ..ListFunctionsRequest::default()
            }))
            .await?;
        assert_eq!(
            invalid.structured_content.unwrap_or_default()["error"]["code"],
            "invalid_input",
            "invalid paging is rejected before the scoped read"
        );
        let filtered = server
            .list_functions(Parameters(ListFunctionsRequest {
                device: Some("ssh".into()),
                ..ListFunctionsRequest::default()
            }))
            .await?;
        assert_eq!(filtered.is_error, Some(true));
        assert_eq!(
            filtered.structured_content,
            Some(json!({"error": {
                "code": "knowledge_error",
                "message": Error::Knowledge("scoped catalog was loaded".into()).to_string(),
                "diagnostics": []
            }})),
        );
        Ok(())
    }

    #[tokio::test]
    async fn script_device_misses_suggest_and_alias_only_after_an_exact_miss()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::model::Function;
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn functions() -> Vec<Function> {
            vec![
                Function {
                    source: "BUILT-IN".into(),
                    interface: "SSH".into(),
                    name: "OPEN".into(),
                    convention: Some(1),
                    ..Function::default()
                },
                Function {
                    source: "DLL".into(),
                    interface: "WIFI_TEST".into(),
                    name: "TX".into(),
                    convention: Some(2),
                    ..Function::default()
                },
            ]
        }

        /// Scoped reads return only the addressed rows, like `PostgresCatalog`.
        #[derive(Default)]
        struct PartialCatalog {
            interface_reads: AtomicUsize,
        }

        impl PartialCatalog {
            fn scoped(&self, device: &str, name: Option<&str>) -> EngineResult<Snapshot> {
                let (source, interface) = crate::device_target(device)?;
                Ok(Snapshot {
                    functions: functions()
                        .into_iter()
                        .filter(|function| {
                            function.source == source
                                && function.interface.eq_ignore_ascii_case(interface)
                                && name.is_none_or(|name| function.name.eq_ignore_ascii_case(name))
                        })
                        .collect(),
                    ..Snapshot::default()
                })
            }
        }

        impl Catalog for PartialCatalog {
            fn snapshot(&self) -> EngineResult<Snapshot> {
                Err(Error::Knowledge("full snapshot must not be loaded".into()))
            }

            fn device_snapshot(&self, device: &str) -> EngineResult<Snapshot> {
                self.scoped(device, None)
            }

            fn function_snapshot(&self, device: &str, name: &str) -> EngineResult<Snapshot> {
                self.scoped(device, Some(name))
            }

            fn interfaces(&self) -> EngineResult<Vec<(String, String)>> {
                self.interface_reads.fetch_add(1, Ordering::SeqCst);
                Ok(crate::devices::interfaces(&functions()))
            }
        }

        let catalog = Arc::new(PartialCatalog::default());
        let server = McpServer::new(catalog.clone());
        let list = |device: &str| {
            server.list_functions(Parameters(ListFunctionsRequest {
                device: Some(device.into()),
                ..ListFunctionsRequest::default()
            }))
        };
        let get = |device: &str| {
            server.get_function(Parameters(GetFunctionRequest {
                device: device.into(),
                name: "TX".into(),
                device_scope: None,
            }))
        };

        let exact = list("SSH").await?;
        assert_ne!(exact.is_error, Some(true), "{exact:?}");
        let exact = exact.structured_content.unwrap_or_default();
        assert_eq!(exact["script_device"], "SSH");
        assert_eq!(exact["matched_by"], "script_device");
        assert_eq!(catalog.interface_reads.load(Ordering::SeqCst), 0);

        let aliased = list("wifi_test").await?;
        assert_ne!(aliased.is_error, Some(true), "{aliased:?}");
        let aliased = aliased.structured_content.unwrap_or_default();
        assert_eq!(aliased["functions"][0]["name"], "TX");
        assert_eq!(aliased["script_device"], "DLLWIFI_TEST");
        assert_eq!(aliased["matched_by"], "interface");
        assert_eq!(catalog.interface_reads.load(Ordering::SeqCst), 1);

        let unknown = list("WIFI").await?;
        assert_eq!(unknown.is_error, Some(true));
        assert_eq!(
            unknown.structured_content,
            Some(json!({"error": {
                "code": "unknown_device",
                "message": "unknown device: WIFI",
                "diagnostics": [],
                "candidates": ["DLLWIFI_TEST"]
            }}))
        );

        let point = get("WIFI_TEST").await?;
        assert_ne!(point.is_error, Some(true), "{point:?}");
        let point = point.structured_content.unwrap_or_default();
        assert_eq!(point["function"]["name"], "TX");
        assert_eq!(point["matched_by"], "interface");

        let missing = get("WIFI").await?;
        assert_eq!(
            missing.structured_content,
            Some(json!({"error": {
                "code": "unknown_function",
                "message": "unknown function: WIFI/TX",
                "diagnostics": [],
                "candidates": ["DLLWIFI_TEST"]
            }}))
        );

        let line = server
            .compose_line(Parameters(ComposeRequest {
                device: "WIFI_TEST".into(),
                function: "TX".into(),
                device_scope: None,
                params: Default::default(),
                criteria: Default::default(),
                param_sections: Vec::new(),
                criteria_sections: Vec::new(),
                timeout: 1,
                pass_path: None,
                fail_path: None,
                error_code: None,
            }))
            .await?;
        assert_eq!(
            line.structured_content,
            Some(json!({"error": {
                "code": "unknown_function",
                "message": "unknown function: WIFI_TEST/TX",
                "diagnostics": [],
                "candidates": ["DLLWIFI_TEST"]
            }}))
        );
        Ok(())
    }

    #[tokio::test]
    async fn device_listing_and_readiness_read_only_example_free_snapshots()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::model::Function;

        struct ExampleFreeCatalog;

        impl ExampleFreeCatalog {
            fn functions() -> Snapshot {
                Snapshot {
                    functions: vec![Function {
                        source: "DLL".into(),
                        interface: "WIFI_TEST".into(),
                        name: "TX".into(),
                        convention: Some(2),
                        ..Function::default()
                    }],
                    ..Snapshot::default()
                }
            }
        }

        impl Catalog for ExampleFreeCatalog {
            fn snapshot(&self) -> EngineResult<Snapshot> {
                Err(Error::Knowledge("examples must not be loaded".into()))
            }

            fn snapshot_without_examples(&self) -> EngineResult<Snapshot> {
                Ok(Self::functions())
            }

            fn device_snapshot(&self, device: &str) -> EngineResult<Snapshot> {
                self.function_snapshot_without_examples(device, "")
            }

            fn function_snapshot(&self, _: &str, _: &str) -> EngineResult<Snapshot> {
                Err(Error::Knowledge("examples must not be loaded".into()))
            }

            fn function_snapshot_without_examples(
                &self,
                device: &str,
                _: &str,
            ) -> EngineResult<Snapshot> {
                Ok(if device.eq_ignore_ascii_case("DLLWIFI_TEST") {
                    Self::functions()
                } else {
                    Snapshot::default()
                })
            }
        }

        let server = McpServer::new(Arc::new(ExampleFreeCatalog));
        let devices = server.list_devices().await?;
        assert_eq!(
            devices.structured_content,
            Some(json!({"devices": [{
                "script_device": "DLLWIFI_TEST",
                "source": "DLL",
                "interface": "WIFI_TEST",
                "mode_suffixes": ["QUICK", "PROXY"],
                "function_count": 1,
                "composable_count": 0
            }]}))
        );

        let readiness = server
            .get_function_readiness(Parameters(GetFunctionRequest {
                device: "wifi_test".into(),
                name: "TX".into(),
                device_scope: None,
            }))
            .await?;
        assert_ne!(readiness.is_error, Some(true), "{readiness:?}");
        let readiness = readiness.structured_content.unwrap_or_default();
        assert_eq!(readiness["status"], "not_ready");
        assert_eq!(readiness["script_device"], "DLLWIFI_TEST");
        assert_eq!(readiness["matched_by"], "interface");

        let device = server
            .get_device(Parameters(GetDeviceRequest {
                device: "WIFI_TEST".into(),
            }))
            .await?;
        assert_ne!(device.is_error, Some(true), "{device:?}");
        let device = device.structured_content.unwrap_or_default();
        assert_eq!(device["script_device"], "DLLWIFI_TEST");
        assert_eq!(device["matched_by"], "interface");
        assert_eq!(
            device["readiness"],
            json!({"ready": 0, "bundle_ready": 0, "not_ready": 1})
        );

        let fields = server
            .list_function_fields(Parameters(ListFunctionFieldsRequest {
                device: "DLLWIFI_TEST".into(),
                function: None,
                device_scope: None,
            }))
            .await?;
        assert_eq!(
            fields.structured_content.unwrap_or_default()["functions"][0]["name"],
            "TX"
        );
        for kind in ["parameter", "criterion"] {
            let request = || -> serde_json::Result<DefinitionRequest> {
                serde_json::from_value(json!({"kind": kind, "name": "ANT"}))
            };
            let definition = server.get_definition(Parameters(request()?)).await?;
            assert_ne!(definition.is_error, Some(true), "{definition:?}");
            let users = server.find_functions_using(Parameters(request()?)).await?;
            assert_eq!(
                users.structured_content.unwrap_or_default()["functions"],
                json!([])
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_device_point_lookups_skip_catalog() -> std::result::Result<(), ErrorData> {
        let server = McpServer::new(Arc::new(UnavailableCatalog));
        let device = "DLLIOT#INVALID";
        let function = "READ";
        let message = "invalid device: only DLL #QUICK and #PROXY mode suffixes are supported";
        let compose = ComposeRequest {
            device: device.into(),
            function: function.into(),
            device_scope: None,
            params: Default::default(),
            criteria: Default::default(),
            param_sections: Vec::new(),
            criteria_sections: Vec::new(),
            timeout: 1,
            pass_path: None,
            fail_path: None,
            error_code: None,
        };
        let results = [
            server
                .get_function(Parameters(GetFunctionRequest {
                    device: device.into(),
                    name: function.into(),
                    device_scope: None,
                }))
                .await?,
            server
                .suggest_criteria(Parameters(SuggestCriteriaRequest {
                    device: device.into(),
                    function: function.into(),
                    device_scope: None,
                }))
                .await?,
            server.compose_line(Parameters(compose)).await?,
        ];
        let expected = Some(json!({ "error": {
            "code": "invalid_input", "message": message, "diagnostics": []
        }}));
        for result in results {
            assert_eq!(result.is_error, Some(true));
            assert_eq!(result.structured_content, expected);
        }

        let result = server
            .validate_line(Parameters(ValidateLineRequest {
                line: format!("{device}|{function}||NULL|1"),
                device_scope: None,
            }))
            .await?;
        assert_ne!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content,
            Some(json!({
                "status": "invalid",
                "segments": [device, function, "", "NULL", "1"],
                "diagnostics": [
                    { "field": "function", "code": "unsupported_convention",
                      "message": "function convention is missing or unsupported", "severity": "incomplete" },
                    { "field": "device", "code": "invalid_input", "message": message, "severity": "error" }
                ]
            }))
        );
        Ok(())
    }
}
