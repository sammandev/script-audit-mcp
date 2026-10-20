use std::sync::Arc;

use rmcp::{
    ErrorData, ServerHandler, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Catalog, Engine, Error, Result as EngineResult, model::ComposeRequest};

#[derive(Clone)]
pub struct McpServer {
    catalog: Arc<dyn Catalog>,
}

#[tool_handler(name = "Script Audit")]
impl ServerHandler for McpServer {}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListFunctionsRequest {
    pub device: Option<String>,
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

#[tool_router]
impl McpServer {
    pub fn new(catalog: Arc<dyn Catalog>) -> Self {
        Self { catalog }
    }

    #[tool(
        description = "List catalog functions, conventions, categories, and composition support. Device is a script token, not a scope.",
        annotations(read_only_hint = true)
    )]
    pub async fn list_functions(
        &self,
        Parameters(request): Parameters<ListFunctionsRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(move |engine| {
            let functions = engine.list_functions(request.device.as_deref())?;
            Ok(serde_json::json!({"functions": functions}))
        })
        .await
    }

    #[tool(
        description = "Read full scoped parameter and criteria definitions, patterns, defaults, required flags, and stored examples. No defaults are applied.",
        annotations(read_only_hint = true)
    )]
    pub async fn get_function(
        &self,
        Parameters(request): Parameters<GetFunctionRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(move |engine| {
            engine.get_function(
                &request.device,
                &request.name,
                request.device_scope.as_deref(),
            )
        })
        .await
    }

    #[tool(
        description = "Read known criteria definitions and recorded usage examples without inventing thresholds.",
        annotations(read_only_hint = true)
    )]
    pub async fn suggest_criteria(
        &self,
        Parameters(request): Parameters<SuggestCriteriaRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(move |engine| {
            engine.suggest_criteria(
                &request.device,
                &request.function,
                request.device_scope.as_deref(),
            )
        })
        .await
    }

    #[tool(
        description = "Compose a validated five/eight-field script line using an audited profile. SINGLE values are strings and MULTIPLE values are string arrays. This tool never executes scripts.",
        annotations(read_only_hint = true)
    )]
    pub async fn compose_line(
        &self,
        Parameters(request): Parameters<ComposeRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(move |engine| engine.compose_line(request))
            .await
    }

    #[tool(
        description = "Check a script line against scoped knowledge. Report valid, invalid, or incomplete and preserve original fields; historical seven/nine-field lines warn. Runtime references are never resolved.",
        annotations(read_only_hint = true)
    )]
    pub async fn validate_line(
        &self,
        Parameters(request): Parameters<ValidateLineRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke(move |engine| {
            engine.validate_line(&request.line, request.device_scope.as_deref())
        })
        .await
    }

    #[tool(
        description = "Validate supplied INI bundle text with an explicit dialect and TEST FLOW. Preserves source, reports structural and local branch defects, and identifies incomplete semantic checks. No execution or filesystem access.",
        annotations(read_only_hint = true)
    )]
    pub async fn validate_ini_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::ValidateBundleRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if let Err(error) = request.check_bounds() {
            return Ok(CallToolResult::structured_error(serde_json::json!({
                "error": { "code": error.code(), "message": error.to_string(), "diagnostics": [] }
            })));
        }
        self.invoke(move |engine| crate::bundle::validate(request, &engine))
            .await
    }

    #[tool(
        description = "Compare reviewed sourced requirements with reachable supplied INI behavior. Reports coverage and unresolved conflicts, never certifies document interpretation or hardware execution. No filesystem writes.",
        annotations(read_only_hint = true)
    )]
    pub async fn compare_plan_to_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::plan::ComparePlanRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if let Err(error) = request.check_bounds() {
            return Ok(CallToolResult::structured_error(serde_json::json!({
                "error": { "code": error.code(), "message": error.to_string(), "diagnostics": [] }
            })));
        }
        self.invoke(move |engine| crate::bundle::plan::compare(request, &engine))
            .await
    }

    #[tool(
        description = "Compose a read-only reviewed-base INI draft from sourced requirements and approved templates. Returns exact draft/input identities, draft contents, diffs, validation, coverage, blockers and optional unauthenticated approval-claim metadata. Client human approval is required before client export; never writes, executes or packages scripts.",
        annotations(read_only_hint = true)
    )]
    pub async fn compose_ini_bundle(
        &self,
        Parameters(request): Parameters<crate::bundle::compose::ComposeBundleRequest>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        if let Err(error) = request.check_bounds() {
            return Ok(CallToolResult::structured_error(serde_json::json!({
                "error": { "code": error.code(), "message": error.to_string(), "diagnostics": [] }
            })));
        }
        self.invoke(move |engine| crate::bundle::compose::compose(request, &engine))
            .await
    }
}

impl McpServer {
    async fn invoke<Output: Serialize + Send + 'static>(
        &self,
        operation: impl FnOnce(Engine) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let catalog = Arc::clone(&self.catalog);
        let outcome =
            tokio::task::spawn_blocking(move || operation(Engine::new(catalog.snapshot()?)))
                .await
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        match outcome {
            Ok(output) => serde_json::to_value(output)
                .map(CallToolResult::structured)
                .map_err(|error| ErrorData::internal_error(error.to_string(), None)),
            Err(error) => {
                let diagnostics = if let Error::Validation(issues) = &error {
                    issues.clone()
                } else {
                    Vec::new()
                };
                Ok(CallToolResult::structured_error(serde_json::json!({
                    "error": { "code": error.code(), "message": error.to_string(), "diagnostics": diagnostics }
                })))
            }
        }
    }
}
