use std::sync::Arc;

use rmcp::{
    ErrorData, ServerHandler, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    Catalog, Engine, Error, Result as EngineResult,
    model::{ComposeRequest, Snapshot},
};

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
        let device = request.device.clone();
        let list = move |engine: Engine| {
            let functions = engine.list_functions(request.device.as_deref())?;
            Ok(serde_json::json!({"functions": functions}))
        };
        self.invoke_on(
            move |catalog| match device.as_deref() {
                Some(device) => catalog.device_snapshot(device),
                None => catalog.snapshot_without_examples(),
            },
            list,
        )
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
        let (device, name) = (request.device.clone(), request.name.clone());
        self.invoke_function(device, name, move |engine| {
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
        let (device, name) = (request.device.clone(), request.function.clone());
        self.invoke_function(device, name, move |engine| {
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
        let (device, name) = (request.device.clone(), request.function.clone());
        self.invoke_function_with(
            device,
            name,
            |catalog, device, name| catalog.function_snapshot_without_examples(device, name),
            move |engine| engine.compose_line(request),
        )
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
        self.invoke_on(
            |catalog| catalog.snapshot_without_examples(),
            move |engine| request.validate(&engine),
        )
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

    /// Runs an operation that only looks up the `device`/`name` Function.
    async fn invoke_function<Output: Serialize + Send + 'static>(
        &self,
        device: String,
        name: String,
        operation: impl FnOnce(Engine) -> EngineResult<Output> + Send + 'static,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        self.invoke_function_with(
            device,
            name,
            |catalog, device, name| catalog.function_snapshot(device, name),
            operation,
        )
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
        let catalog = Arc::clone(&self.catalog);
        let outcome =
            tokio::task::spawn_blocking(move || operation(Engine::new(load(catalog.as_ref())?)))
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

fn domain_error(error: Error) -> CallToolResult {
    let diagnostics = match &error {
        Error::Validation(issues) => issues.as_slice(),
        _ => &[],
    };
    CallToolResult::structured_error(serde_json::json!({
        "error": { "code": error.code(), "message": error.to_string(), "diagnostics": diagnostics }
    }))
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
            .list_functions(Parameters(ListFunctionsRequest { device: None }))
            .await?;
        assert_eq!(broad.structured_content, Some(json!({"functions": []})));
        let filtered = server
            .list_functions(Parameters(ListFunctionsRequest {
                device: Some("ssh".into()),
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
