use std::collections::BTreeMap;

use script_audit_mcp::model::{
    ComposeRequest, CriteriaInput, Definition, Example, Function, Link, Snapshot, ValidationStatus,
    Value,
};
use script_audit_mcp::{Engine, Result};

fn fixture_snapshot() -> Snapshot {
    Snapshot {
        functions: vec![
            Function {
                source: "BUILT-IN".into(),
                interface: "SSH".into(),
                name: "OPEN".into(),
                convention: Some(1),
                category: "communication".into(),
                ..Function::default()
            },
            Function {
                source: "DLL".into(),
                interface: "WIFI_TEST".into(),
                name: "TX_MULTI_VERIFICATION".into(),
                convention: Some(2),
                category: "instrument_control".into(),
                ..Function::default()
            },
        ],
        parameter_definitions: vec![
            Definition {
                name: "ANT".into(),
                device_name: "WIFI_TEST".into(),
                kind: "int".into(),
                cardinality: "MULTIPLE".into(),
                value_pattern: "<ant1>,<ant2>...".into(),
                allowed_values: "{15,2}".into(),
                default_value: Some("15".into()),
                ..Definition::default()
            },
            Definition {
                name: "SESSION_PAYLOAD".into(),
                device_name: "SSH".into(),
                kind: "string".into(),
                cardinality: "SINGLE".into(),
                value_pattern: "<session>@<payload>".into(),
                ..Definition::default()
            },
        ],
        parameter_links: vec![
            Link {
                name: "ANT".into(),
                function_source: "DLL".into(),
                function_name: "TX_MULTI_VERIFICATION".into(),
                device_name: "WIFI_TEST".into(),
                position: Some(1),
                required: true,
            },
            Link {
                name: "SESSION_PAYLOAD".into(),
                function_source: "BUILT-IN".into(),
                function_name: "OPEN".into(),
                device_name: "SSH".into(),
                position: Some(1),
                required: true,
            },
        ],
        criteria_definitions: vec![
            Definition {
                name: "POWER".into(),
                kind: "double".into(),
                cardinality: "SINGLE".into(),
                unit: "dB".into(),
                value_pattern: "<power>dB".into(),
                allowed_values: "[0..10]".into(),
                ..Definition::default()
            },
            Definition {
                name: "EXPECTED_RESPONSE".into(),
                device_name: "SSH".into(),
                kind: "string".into(),
                cardinality: "SINGLE".into(),
                value_pattern: "<prompt>".into(),
                ..Definition::default()
            },
        ],
        criteria_links: vec![
            Link {
                name: "POWER".into(),
                function_source: "DLL".into(),
                function_name: "TX_MULTI_VERIFICATION".into(),
                device_name: "WIFI_TEST".into(),
                position: Some(1),
                required: false,
            },
            Link {
                name: "EXPECTED_RESPONSE".into(),
                function_source: "BUILT-IN".into(),
                function_name: "OPEN".into(),
                device_name: "SSH".into(),
                position: Some(1),
                required: false,
            },
        ],
        examples: vec![Example {
            function_source: "DLL".into(),
            device_name: "WIFI_TEST".into(),
            function_name: "TX_MULTI_VERIFICATION".into(),
            script: "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|".into(),
            meaning: "Fixture: verify antennas".into(),
        }],
    }
}

fn fixture() -> Engine {
    Engine::new(fixture_snapshot())
}

#[test]
fn list_functions_filters_script_device_and_exposes_convention() -> Result<()> {
    let functions = fixture().list_functions(Some("SSH"))?;
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name, "OPEN");
    assert_eq!(functions[0].convention, Some(1));
    assert_eq!(functions[0].category, "communication");
    Ok(())
}

#[test]
fn get_function_resolves_scoped_schema_and_preserves_examples() -> Result<()> {
    let schema = fixture().get_function("DLLWIFI_TEST#QUICK", "TX_MULTI_VERIFICATION", None)?;
    assert_eq!(schema.device_scope, "WIFI_TEST");
    assert_eq!(schema.parameters.len(), 1);
    assert!(schema.parameters[0].required);
    let definition = schema.parameters[0].definition.as_ref().ok_or_else(|| {
        script_audit_mcp::Error::Knowledge("fixture definition is missing".into())
    })?;
    assert_eq!(definition.value_pattern, "<ant1>,<ant2>...");
    assert_eq!(definition.default_value.as_deref(), Some("15"));
    assert_eq!(definition.cardinality, "MULTIPLE");
    assert_eq!(
        schema.examples[0].script,
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|"
    );
    Ok(())
}

#[test]
fn suggest_criteria_returns_known_patterns_and_examples() -> Result<()> {
    let suggestions = fixture().suggest_criteria("DLLWIFI_TEST", "TX_MULTI_VERIFICATION", None)?;
    assert_eq!(suggestions.criteria.len(), 1);
    assert_eq!(suggestions.criteria[0].name, "POWER");
    let definition = suggestions.criteria[0]
        .definition
        .as_ref()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("fixture criterion is missing".into()))?;
    assert_eq!(definition.value_pattern, "<power>dB");
    assert_eq!(suggestions.examples.len(), 1);
    Ok(())
}

fn wifi_request() -> ComposeRequest {
    ComposeRequest {
        device: "DLLWIFI_TEST".into(),
        function: "TX_MULTI_VERIFICATION".into(),
        device_scope: None,
        params: BTreeMap::from([("ANT".into(), Value::Multiple(vec!["15".into(), "2".into()]))]),
        criteria: CriteriaInput::Named(BTreeMap::from([(
            "POWER".into(),
            Value::Single("5dB".into()),
        )])),
        timeout: 20000,
        pass_path: Some("NEXT".into()),
        fail_path: Some("FAIL".into()),
        error_code: None,
    }
}

#[test]
fn compose_line_emits_eight_fields_and_preserves_empty_error_code() -> Result<()> {
    let result = fixture().compose_line(wifi_request())?;
    assert_eq!(
        result.line,
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|20000|NEXT|FAIL|"
    );
    assert!(result.warnings.is_empty());
    Ok(())
}

#[test]
fn validate_line_checks_eight_fields_without_losing_trailing_empty_field() -> Result<()> {
    let report = fixture().validate_line(
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|20000|NEXT|FAIL|",
        None,
    )?;
    assert_eq!(report.status, ValidationStatus::Valid);
    assert_eq!(report.segments.len(), 8);
    assert_eq!(report.segments[7], "");
    assert!(report.diagnostics.is_empty());
    Ok(())
}

#[test]
fn catalog_reports_audited_composition_support() -> Result<()> {
    let functions = fixture().list_functions(Some("DLLWIFI_TEST"))?;
    assert!(functions[0].composition_supported);
    Ok(())
}

#[test]
fn compose_raw_payload_preserves_shell_characters_and_emits_five_fields() -> Result<()> {
    let request = ComposeRequest {
        device: "SSH".into(),
        function: "OPEN".into(),
        device_scope: None,
        params: BTreeMap::from([(
            "SESSION_PAYLOAD".into(),
            Value::Single("DUT@echo a=b&next".into()),
        )]),
        criteria: CriteriaInput::Raw("root#".into()),
        timeout: 5000,
        pass_path: None,
        fail_path: None,
        error_code: None,
    };
    let result = fixture().compose_line(request)?;
    assert_eq!(result.line, "SSH|OPEN|DUT@echo a=b&next|root#|5000");
    assert_eq!(
        fixture().validate_line(&result.line, None)?.status,
        ValidationStatus::Valid
    );
    Ok(())
}

#[test]
fn compose_rejects_invalid_values_and_does_not_fill_defaults() {
    let mut requests = Vec::new();
    let mut missing = wifi_request();
    missing.params.clear();
    requests.push(missing);
    let mut wrong_count = wifi_request();
    wrong_count
        .params
        .insert("ANT".into(), Value::Single("15,2".into()));
    requests.push(wrong_count);
    let mut outside_set = wifi_request();
    outside_set
        .params
        .insert("ANT".into(), Value::Multiple(vec!["999".into()]));
    requests.push(outside_set);
    let mut injection = wifi_request();
    injection
        .params
        .insert("ANT".into(), Value::Multiple(vec!["15&EXTRA=1".into()]));
    requests.push(injection);
    let mut wrong_pattern = wifi_request();
    wrong_pattern.criteria = CriteriaInput::Named(BTreeMap::from([(
        "POWER".into(),
        Value::Single("5".into()),
    )]));
    requests.push(wrong_pattern);
    let mut zero_timeout = wifi_request();
    zero_timeout.timeout = 0;
    requests.push(zero_timeout);
    let mut unknown_parameter = wifi_request();
    unknown_parameter
        .params
        .insert("UNKNOWN".into(), Value::Single("x".into()));
    requests.push(unknown_parameter);
    let mut pipe_in_flow = wifi_request();
    pipe_in_flow.pass_path = Some("NEXT|EXTRA".into());
    requests.push(pipe_in_flow);
    for request in requests {
        assert!(matches!(
            fixture().compose_line(request),
            Err(script_audit_mcp::Error::Validation(_))
        ));
    }
}

#[test]
fn unknown_criteria_are_preserved_with_warnings() -> Result<()> {
    let mut request = wifi_request();
    request.criteria = CriteriaInput::Named(BTreeMap::from([(
        "Remainder".into(),
        Value::Single("0".into()),
    )]));
    let result = fixture().compose_line(request)?;
    assert!(result.line.contains("|Remainder=0|"));
    assert_eq!(result.warnings[0].code, "unknown_criteria_key");
    let report = fixture().validate_line(&result.line, None)?;
    assert_eq!(report.status, ValidationStatus::Valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|issue| issue.code == "unknown_criteria_key")
    );
    Ok(())
}

#[test]
fn historical_widths_preserve_all_fields_and_warn() -> Result<()> {
    for line in [
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL",
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|E001|description",
    ] {
        let report = fixture().validate_line(line, None)?;
        assert_eq!(report.status, ValidationStatus::Valid);
        assert_eq!(report.segments.join("|"), line);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|issue| issue.code == "historical_width")
        );
    }
    Ok(())
}

#[test]
fn validation_rejects_duplicate_keys_unknown_functions_and_wrong_width() -> Result<()> {
    for line in [
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15&ANT=2|NULL|20000|NEXT|FAIL|",
        "DLLWIFI_TEST|UNKNOWN|ANT=15|NULL|20000|NEXT|FAIL|",
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15|NULL|20000",
        "SSH|OPEN|DUT@payload|NULL|5000|NEXT|FAIL|",
        "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,,2|NULL|20000|NEXT|FAIL|",
    ] {
        assert_eq!(
            fixture().validate_line(line, None)?.status,
            ValidationStatus::Invalid
        );
    }
    Ok(())
}

#[test]
fn unsupported_patterns_and_orphans_are_incomplete_not_valid() -> Result<()> {
    for orphan in [false, true] {
        let mut snapshot = fixture_snapshot();
        if orphan {
            snapshot
                .parameter_definitions
                .retain(|definition| definition.name != "ANT");
        } else {
            snapshot.parameter_definitions[0].value_pattern = "[<ant>]".into();
        }
        let engine = Engine::new(snapshot);
        assert!(
            !engine
                .get_function("DLLWIFI_TEST", "TX_MULTI_VERIFICATION", None)?
                .function
                .composition_supported
        );
        assert!(matches!(
            engine.compose_line(wifi_request()),
            Err(script_audit_mcp::Error::Validation(_))
        ));
        assert_eq!(
            engine
                .validate_line(
                    "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|",
                    None
                )?
                .status,
            ValidationStatus::Incomplete
        );
        assert_eq!(
            engine
                .validate_line(
                    "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|POWER=bad|0|NEXT|FAIL|",
                    None
                )?
                .status,
            ValidationStatus::Invalid
        );
    }
    Ok(())
}

#[test]
fn engine_references_are_preserved_without_runtime_resolution() -> Result<()> {
    let mut request = wifi_request();
    request
        .params
        .insert("ANT".into(), Value::Multiple(vec!["*I:ANT_PATH".into()]));
    let result = fixture().compose_line(request)?;
    assert!(result.line.contains("ANT=*I:ANT_PATH"));
    assert!(
        result
            .warnings
            .iter()
            .any(|issue| issue.code == "runtime_reference_unchecked")
    );
    let mut invalid = wifi_request();
    invalid
        .params
        .insert("ANT".into(), Value::Multiple(vec!["*I:".into()]));
    assert!(fixture().compose_line(invalid).is_err());
    Ok(())
}

#[test]
fn explicit_scope_uses_matching_links_and_global_definition_fallback() -> Result<()> {
    let mut snapshot = fixture_snapshot();
    let mut global = snapshot.parameter_definitions[0].clone();
    global.device_name.clear();
    global.allowed_values = "{1}".into();
    global.required = true;
    snapshot.parameter_definitions.push(global);
    let mut link = snapshot.parameter_links[0].clone();
    link.device_name = "IOT".into();
    link.required = false;
    snapshot.parameter_links.push(link);
    let engine = Engine::new(snapshot);
    let schema = engine.get_function("DLLWIFI_TEST", "TX_MULTI_VERIFICATION", Some("iot"))?;
    assert_eq!(schema.parameters.len(), 1);
    assert!(!schema.parameters[0].required);
    assert_eq!(
        schema.parameters[0]
            .definition
            .as_ref()
            .map(|definition| definition.allowed_values.as_str()),
        Some("{1}")
    );
    assert!(schema.criteria.is_empty());
    Ok(())
}

#[cfg(feature = "mcp")]
struct MemoryCatalog;

#[cfg(feature = "mcp")]
impl script_audit_mcp::Catalog for MemoryCatalog {
    fn snapshot(&self) -> Result<Snapshot> {
        Ok(fixture_snapshot())
    }
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_catalog_tool_returns_structured_data() -> Result<()> {
    use rmcp::handler::server::wrapper::Parameters;
    use script_audit_mcp::mcp::{ListFunctionsRequest, McpServer};
    let server = McpServer::new(std::sync::Arc::new(MemoryCatalog));
    let result = server
        .list_functions(Parameters(ListFunctionsRequest {
            device: Some("SSH".into()),
        }))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .and_then(|value| value.get("functions"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_tools_preserve_schemas_lines_and_typed_errors() -> Result<()> {
    use rmcp::handler::server::wrapper::Parameters;
    use script_audit_mcp::mcp::{
        GetFunctionRequest, McpServer, SuggestCriteriaRequest, ValidateLineRequest,
    };
    let server = McpServer::new(std::sync::Arc::new(MemoryCatalog));
    let schema = server
        .get_function(Parameters(GetFunctionRequest {
            device: "DLLWIFI_TEST".into(),
            name: "TX_MULTI_VERIFICATION".into(),
            device_scope: None,
        }))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert!(
        schema
            .structured_content
            .as_ref()
            .is_some_and(|value| value["parameters"][0]["definition"]["cardinality"] == "MULTIPLE")
    );
    let criteria = server
        .suggest_criteria(Parameters(SuggestCriteriaRequest {
            device: "DLLWIFI_TEST".into(),
            function: "TX_MULTI_VERIFICATION".into(),
            device_scope: None,
        }))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert!(
        criteria
            .structured_content
            .as_ref()
            .is_some_and(|value| value["criteria"][0]["name"] == "POWER")
    );
    let composed = server
        .compose_line(Parameters(wifi_request()))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let line = composed
        .structured_content
        .as_ref()
        .and_then(|value| value["line"].as_str())
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("MCP result is missing a line".into()))?;
    let checked = server
        .validate_line(Parameters(ValidateLineRequest {
            line: line.into(),
            device_scope: None,
        }))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert!(
        checked
            .structured_content
            .as_ref()
            .is_some_and(|value| value["status"] == "valid")
    );
    let mut invalid = wifi_request();
    invalid.params.clear();
    let error = server
        .compose_line(Parameters(invalid))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert_eq!(error.is_error, Some(true));
    assert!(
        error
            .structured_content
            .as_ref()
            .is_some_and(|value| value["error"]["code"] == "validation_failed")
    );
    Ok(())
}

#[test]
fn compose_rejects_criteria_keys_that_cannot_round_trip() {
    let mut request = wifi_request();
    request.criteria = CriteriaInput::Named(BTreeMap::from([(
        " Remainder ".into(),
        Value::Single("0".into()),
    )]));
    assert!(fixture().compose_line(request).is_err());
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_protocol_advertises_and_dispatches_tools() -> Result<()> {
    use rmcp::ServiceExt;
    use serde_json::{Value as JsonValue, json};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

    async fn send(writer: &mut WriteHalf<DuplexStream>, value: JsonValue) -> Result<()> {
        let mut payload = serde_json::to_vec(&value)
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
        payload.push(b'\n');
        writer.write_all(&payload).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn receive(reader: &mut BufReader<ReadHalf<DuplexStream>>) -> Result<JsonValue> {
        let mut payload = String::new();
        if reader.read_line(&mut payload).await? == 0 {
            return Err(script_audit_mcp::Error::Knowledge(
                "MCP peer closed before a response".into(),
            ));
        }
        serde_json::from_str(&payload)
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))
    }

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let server = script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(MemoryCatalog));
        let task = tokio::spawn(async move {
            let service = server.serve(tokio::io::split(server_stream)).await
                .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
            service.waiting().await.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
            Ok::<(), script_audit_mcp::Error>(())
        });
        let (input, mut output) = tokio::io::split(client_stream);
        let mut input = BufReader::new(input);
        send(&mut output, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture-client","version":"1"}
        }})).await?;
        let initialized = receive(&mut input).await?;
        assert_eq!(initialized["id"], 1);
        assert_eq!(initialized["result"]["serverInfo"]["name"], "Script Audit");
        assert!(initialized["result"]["capabilities"]["tools"].is_object());
        send(&mut output, json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await?;
        send(&mut output, json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = receive(&mut input).await?;
        let tools = listed["result"]["tools"].as_array()
            .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing tool discovery result".into()))?;
        assert_eq!(tools.len(), 8);
        for name in ["list_functions", "get_function", "suggest_criteria", "compose_line", "validate_line", "validate_ini_bundle", "compare_plan_to_bundle", "compose_ini_bundle"] {
            assert!(tools.iter().any(|tool| tool["name"] == name && tool["annotations"]["readOnlyHint"] == true));
        }
        assert!(tools.iter().any(|tool| tool["name"] == "compose_ini_bundle"
            && tool["inputSchema"]["properties"]["procedure_templates"].is_object()));
        assert!(tools.iter().any(|tool| tool["name"] == "compose_ini_bundle"
            && tool["inputSchema"]["properties"]["draft_approval"].is_object()));
        for case in ["missing_variant", "missing_selected_flow", "automatic_variant", "oversized_policy", "too_many_policy_sources"] {
            let mut arguments = compose_bundle_arguments();
            match case {
                "missing_variant" => { arguments["comparison"].as_object_mut().map(|fields| fields.remove("flow_variant")); }
                "missing_selected_flow" => { arguments["comparison"]["bundle"].as_object_mut().map(|fields| fields.remove("selected_flow")); }
                "automatic_variant" => arguments["comparison"]["flow_variant"] = json!("automatic"),
                _ => {
                    arguments["comparison"]["plan"]["sampling_policy"] = json!({"rate":{"value":5,"unit":"%"},
                        "schedule":if case == "oversized_policy" { "x".repeat(4097) } else { "synthetic shift".into() },
                        "provenance":if case == "too_many_policy_sources" { vec![json!({"source_id":"plan","revision":"3.8","excerpt":"synthetic"}); 33] } else { vec![] }});
                }
            }
            send(&mut output, json!({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{
                "name":"compose_ini_bundle","arguments":arguments
            }})).await?;
            let rejected = receive(&mut input).await?;
            assert!(rejected["error"].is_null(), "{case}: {rejected}");
            assert_eq!(rejected["result"]["isError"], true, "{case}: {rejected}");
        }
        let mut composition = compose_bundle_arguments();
        composition["procedure_templates"] = json!([procedure_pack("TX-OFDM6", "DLLWIFI_TEST", "RX_VERIFY_PER")]);
        send(&mut output, json!({"jsonrpc":"2.0","id":29,"method":"tools/call","params":{
            "name":"compose_ini_bundle","arguments":composition
        }})).await?;
        let preview = receive(&mut input).await?;
        assert_ne!(preview["result"]["isError"], true, "{preview}");
        let preview = &preview["result"]["structuredContent"];
        assert_eq!(preview["ready_for_review"], false);
        assert_eq!(preview["draft_files"], composition["comparison"]["bundle"]["files"]);
        assert_eq!(preview["diffs"], json!([]));
        assert!(preview["blockers"].as_array().is_some_and(|items| !items.is_empty()));
        assert_eq!(preview["draft_approval"]["status"], "not_supplied");
        composition["draft_approval"] = json!({"subject_identity":preview["draft_identity"],
            "approver":"fixture reviewer", "evidence":"fixture only", "kind":"operator_review"});
        send(&mut output, json!({"jsonrpc":"2.0","id":36,"method":"tools/call","params":{
            "name":"compose_ini_bundle","arguments":composition
        }})).await?;
        let claimed = receive(&mut input).await?;
        assert_eq!(claimed["result"]["structuredContent"]["draft_approval"]["status"], "blocked");
        assert_eq!(claimed["result"]["structuredContent"]["export"], "not_performed");
        for (field, value) in [("approved", json!(true)), ("output_path", json!("./working.ini")), ("draft_approval", json!(true))] {
            let mut malformed = composition.clone();
            malformed[field] = value;
            send(&mut output, json!({"jsonrpc":"2.0","id":37,"method":"tools/call","params":{
                "name":"compose_ini_bundle","arguments":malformed
            }})).await?;
            let rejected = receive(&mut input).await?;
            assert!(rejected["error"].is_null(), "{rejected}");
            assert_eq!(rejected["result"]["isError"], true, "{rejected}");
        }
        send(&mut output, json!({"jsonrpc":"2.0","id":26,"method":"tools/call","params":{
            "name":"compare_plan_to_bundle","arguments":tx_plan_arguments()
        }})).await?;
        let compared = receive(&mut input).await?;
        assert_ne!(compared["result"]["isError"], true, "{compared}");
        assert_eq!(compared["result"]["structuredContent"]["coverage"][0]["status"], "unknown");
        assert_eq!(compared["result"]["structuredContent"]["ready_for_review"], false);
        for arguments in [rx_plan_arguments(), calibration_plan_arguments(), bluetooth_rx_arguments()] {
            send(&mut output, json!({"jsonrpc":"2.0","id":28,"method":"tools/call","params":{
                "name":"compare_plan_to_bundle","arguments":arguments
            }})).await?;
            let response = receive(&mut input).await?;
            assert_ne!(response["result"]["isError"], true, "{response}");
            assert!(response["result"]["structuredContent"]["coverage"].is_array(), "{response}");
            assert_eq!(response["result"]["structuredContent"]["ready_for_review"], false);
        }
        for arguments in [json!({"bundle":bundle_arguments(""),"plan":{},"flow_variant":"normal"}), json!({"execute":true})] {
            send(&mut output, json!({"jsonrpc":"2.0","id":27,"method":"tools/call","params":{
                "name":"compare_plan_to_bundle","arguments":arguments
            }})).await?;
            let rejected = receive(&mut input).await?;
            assert!(rejected["error"].is_null(), "{rejected}");
            assert_eq!(rejected["result"]["isError"], true, "{rejected}");
        }
        for (index, (name, arguments)) in [
            ("list_functions", json!({"device":"SSH"})),
            ("get_function", json!({"device":"DLLWIFI_TEST","name":"TX_MULTI_VERIFICATION"})),
            ("suggest_criteria", json!({"device":"DLLWIFI_TEST","function":"TX_MULTI_VERIFICATION"})),
            ("compose_line", serde_json::to_value(wifi_request()).map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?),
            ("validate_line", json!({"line":"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|"})),
        ].into_iter().enumerate() {
            let request_id = index + 3;
            send(&mut output, json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
            let response = receive(&mut input).await?;
            assert_eq!(response["id"], request_id);
            assert!(response["error"].is_null(), "{response}");
            assert_ne!(response["result"]["isError"], true, "{response}");
            assert!(response["result"]["structuredContent"].is_object(), "{response}");
        }
        let source = concat!(
            "; sanitized regression\n[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n",
            "A = \"DLLQSPR#QUICK|FUNC|ANT=1|POWER=5dB|NULL|SET_IPLAS_INFO|FAIL\n",
            "B = \"DLLQSPR|FUNC|NULL|NULL|100|NEXT|FAIL\n",
            "C = \"DLLQSPR|FUNC|NULL|NULL|100|QUIT|FAIL|Error:opaque\"\n",
        );
        send(&mut output, json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{
            "name":"validate_ini_bundle","arguments":{
                "files":[{"name":"MAIN_FLOW.ini","text":source}],
                "selected_flow":"[TEST FLOW:Normal]","dialect":"hh5k",
                "device_scope":"QSPR","runtime_bindings":[]
            }
        }})).await?;
        let response = receive(&mut input).await?;
        assert!(response["error"].is_null(), "{response}");
        assert_ne!(response["result"]["isError"], true, "{response}");
        let report = &response["result"]["structuredContent"];
        assert_eq!(report["status"], "invalid", "{report}");
        assert_eq!(report["layers"]["structure"], "invalid");
        assert_eq!(report["layers"]["control_flow"], "invalid");
        assert_eq!(report["layers"]["references"], "valid");
        assert_eq!(report["layers"]["catalog"], "invalid");
        let findings = report["diagnostics"].as_array().ok_or_else(||
            script_audit_mcp::Error::Knowledge("missing bundle diagnostics".into()))?;
        assert_eq!(findings.iter().filter(|issue| issue["code"] == "UNTERMINATED_QUOTE").count(), 2);
        assert!(findings.iter().any(|issue| issue["code"] == "BRANCH_TARGET_MISSING"
            && issue["file"] == "MAIN_FLOW.ini" && issue["line"] == 5
            && issue["section"] == "RUN" && issue["row"] == "A"
            && issue["field"] == "pass_path" && issue["evidence"] == "SET_IPLAS_INFO"));
        assert_eq!(report["source_files"][0]["text"], source);
        assert_eq!(report["script_sections"][0]["rows"][0]["parameters"], "ANT=1");
        assert_eq!(report["script_sections"][0]["rows"][0]["criteria"], "POWER=5dB");
        assert_eq!(report["script_sections"][0]["rows"][2]["error_code"], "Error:opaque");
        assert_eq!(report["hardware_verification"], "unchecked");
        assert_eq!(report["packaging"], "unchecked");
        send(&mut output, json!({"jsonrpc":"2.0","id":24,"method":"tools/call","params":{
            "name":"validate_ini_bundle","arguments":{
                "files":[
                    {"name":"MAIN_FLOW.ini","text":"[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"MACRO|READ|CHANNEL=6115|NULL|1|NEXT|FAIL\"\n"},
                    {"name":"MACRO_LIST.ini","text":"[READ]\nSTEP=\"DLL|F|*V:Macro-Param_CHANNEL#|NULL|1|QUIT|FAIL\"\n"}
                ],"selected_flow":"[TEST FLOW:Normal]","dialect":"hh5k"
            }
        }})).await?;
        let response = receive(&mut input).await?;
        assert_ne!(response["result"]["isError"], true, "{response}");
        let report = &response["result"]["structuredContent"];
        assert_eq!(report["layers"]["control_flow"], "valid", "{report}");
        assert_eq!(report["layers"]["references"], "valid", "{report}");
        assert_eq!(report["execution"][1]["parameters"], "6115");
        assert_eq!(report["execution"][1]["call_site"], "row:0");
        send(&mut output, json!({"jsonrpc":"2.0","id":25,"method":"tools/call","params":{
            "name":"validate_ini_bundle","arguments":{
                "files":[{"name":"MAIN_FLOW.ini","text":"[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST#QUICK|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|NULL|QUIT|FAIL|ERRCODE:opaque\"\n"}],
                "selected_flow":"[TEST FLOW:Normal]","dialect":"hh5k"
            }
        }})).await?;
        let response = receive(&mut input).await?;
        assert_ne!(response["result"]["isError"], true, "{response}");
        let report = &response["result"]["structuredContent"];
        assert_eq!(report["status"], "valid", "{report}");
        assert_eq!(report["layers"]["catalog"], "valid", "{report}");
        assert_eq!(report["execution"][0]["device"], "DLLWIFI_TEST#QUICK");
        assert_eq!(report["runtime_verification"], "unchecked");
        send(&mut output, json!({"jsonrpc":"2.0","id":21,"method":"tools/call","params":{
            "name":"validate_ini_bundle","arguments":{
                "files":[],"selected_flow":"[TEST FLOW:Normal]","dialect":"hh5k"
            }
        }})).await?;
        let rejected = receive(&mut input).await?;
        assert!(rejected["error"].is_null(), "{rejected}");
        assert_eq!(rejected["result"]["isError"], true);
        assert_eq!(rejected["result"]["structuredContent"]["error"]["code"], "invalid_input");
        for arguments in [
            json!({"files":[],"selected_flow":"[TEST FLOW:Normal]"}),
            json!({"files":[],"selected_flow":"[TEST FLOW:Normal]","dialect":"guessed"}),
            json!({"files":[],"selected_flow":"[TEST FLOW:Normal]","dialect":"hh5k","execute":true}),
        ] {
            send(&mut output, json!({"jsonrpc":"2.0","id":22,"method":"tools/call","params":{
                "name":"validate_ini_bundle","arguments":arguments
            }})).await?;
            let malformed = receive(&mut input).await?;
            assert!(malformed["error"].is_null(), "{malformed}");
            assert_eq!(malformed["result"]["isError"], true, "{malformed}");
        }
        send(&mut output, json!({"jsonrpc":"2.0","id":23,"method":"method/does-not-exist","params":{}})).await?;
        let malformed = receive(&mut input).await?;
        assert_eq!(malformed["error"]["code"], -32601, "{malformed}");
        assert!(malformed["result"].is_null());
        drop(output);
        drop(input);
        task.await.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))??;
        struct DraftCatalog;
        impl script_audit_mcp::Catalog for DraftCatalog {
            fn snapshot(&self) -> Result<Snapshot> { Ok(tx_plan_snapshot()) }
        }
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let server = script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(DraftCatalog));
        let task = tokio::spawn(async move {
            let service = server.serve(tokio::io::split(server_stream)).await
                .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
            service.waiting().await.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
            Ok::<(), script_audit_mcp::Error>(())
        });
        let (input, mut output) = tokio::io::split(client_stream);
        let mut input = BufReader::new(input);
        send(&mut output, json!({"jsonrpc":"2.0","id":30,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"draft-fixture","version":"1"}
        }})).await?;
        receive(&mut input).await?;
        send(&mut output, json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await?;
        let arguments = reviewed_composition_arguments().await?;
        send(&mut output, json!({"jsonrpc":"2.0","id":31,"method":"tools/call","params":{
            "name":"compose_ini_bundle","arguments":arguments
        }})).await?;
        let response = receive(&mut input).await?;
        assert_ne!(response["result"]["isError"], true, "{response}");
        let draft = &response["result"]["structuredContent"];
        assert!(draft["draft_files"][0]["text"].as_str().is_some_and(|text| text.contains("TX_DRAFT_0=\"TX_DRAFT_0\"\r\n")));
        assert!(draft["draft_files"][5]["text"].as_str().is_some_and(|text| text.contains("TARGET=15.5dBm\nPOWER=-1~2dB\nEVM=<-35dB\n")));
        assert_eq!(draft["draft_files"][2], arguments["comparison"]["bundle"]["files"][2]);
        assert_eq!(draft["comparison"]["mandatory"]["matched"], 1);
        assert_eq!(draft["diffs"].as_array().map(Vec::len), Some(2));
        assert_eq!(draft["ready_for_review"], false);
        for malformed in [json!({"execute":true}), json!({"comparison":{},"flow_anchor":""})] {
            send(&mut output, json!({"jsonrpc":"2.0","id":32,"method":"tools/call","params":{
                "name":"compose_ini_bundle","arguments":malformed
            }})).await?;
            let response = receive(&mut input).await?;
            assert_eq!(response["result"]["isError"], true);
            assert!(response["error"].is_null());
        }
        let mut oversized = arguments.clone();
        oversized["flow_anchor"] = "x".repeat(513).into();
        send(&mut output, json!({"jsonrpc":"2.0","id":33,"method":"tools/call","params":{
            "name":"compose_ini_bundle","arguments":oversized
        }})).await?;
        let rejected = receive(&mut input).await?;
        assert_eq!(rejected["result"]["isError"], true);
        assert_eq!(rejected["result"]["structuredContent"]["error"]["code"], "invalid_input");
        send(&mut output, json!({"jsonrpc":"2.0","id":34,"method":"tools/call","params":{
            "name":"compose_ini_bundle","arguments":arguments
        }})).await?;
        let repeated = receive(&mut input).await?;
        assert_eq!(repeated["result"]["structuredContent"], *draft);
        drop(output);
        drop(input);
        task.await.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))??;
        Ok(())
    }).await.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?
}

#[test]
fn review_regression_empty_optional_values_are_rejected() {
    for raw in ["", " ", "\n"] {
        let mut request = wifi_request();
        request.criteria = CriteriaInput::Named(BTreeMap::from([(
            "POWER".into(),
            Value::Single(raw.into()),
        )]));
        assert!(fixture().compose_line(request).is_err());
    }
}

#[cfg(feature = "mcp")]
fn bundle_arguments(text: &str) -> serde_json::Value {
    serde_json::json!({
        "files": [{"name": "MAIN_FLOW.ini", "text": text}],
        "selected_flow": "[TEST FLOW:Normal]", "dialect": "hh5k"
    })
}

#[cfg(feature = "mcp")]
fn tx_plan_arguments() -> serde_json::Value {
    serde_json::json!({
        "bundle": bundle_arguments(concat!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
            "OFDM6=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|BAND=6G&ANT=1,2,4,8&STANDARD=11AG&FREQ=6115&BW=20&DATA_RATE=OFDM6&TX_TARGET_POWER=15.5dBm&FRAME_COUNT=500|POWER=-1~2dB&EVM=<-35dB|1|QUIT|FAIL\"\n"
        )),
        "flow_variant": "normal",
        "plan": {
            "controlling_source": "plan", "station": "HH5K Wireless Test_2",
            "sources": [{"id":"plan","revision":"3.8","kind":"test_plan","approved":true}],
            "requirements": [{
                "id":"TX-OFDM6", "applicability":"mandatory",
                "provenance":[{"source_id":"plan","revision":"3.8","location":"page 33, Table 17","excerpt":"OFDM6 target 15.5 dBm; EVM strictly below -35 dB"}],
                "test": {
                    "technology":"wifi", "purpose":"tx", "band":"6G", "standard":"11AG",
                    "frequency":{"value":6115,"unit":"MHz"}, "bandwidth":{"value":20,"unit":"MHz"},
                    "rate":"OFDM6", "chains":{"kind":"per_chain","value":[1,2,4,8]},
                    "power_target":{"value":15.5,"unit":"dBm"},
                    "power_tolerance":{"lower":-1,"upper":2,"unit":"dB"},
                    "evm":{"operator":"lt","threshold":{"value":-35,"unit":"dB"}}, "packet_count":500
                }
            }]
        }
    })
}

#[cfg(feature = "mcp")]
fn compose_bundle_arguments() -> serde_json::Value {
    let mut comparison = tx_plan_arguments();
    comparison["bundle"]["files"] = serde_json::json!([
        {"name":"MAIN_FLOW.ini","text":"; synthetic base\n[TEST FLOW:Normal]\n; INSERT TX HERE\nRUN=\"RUN\"\n[RUN]\nKEEP=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=1|NULL|1|QUIT|FAIL\"\n; historical checksum: original-unverified\n"},
        {"name":"MACRO_LIST.ini","text":"; unchanged macros\n"},
        {"name":"FACTORY_SETTING.ini","text":"[STATION]\nEquipment=synthetic\n"},
        {"name":"PARAMETER_LIST.ini","text":"; repeated comments\n; repeated comments\n"},
        {"name":"RD_SETTING.ini","text":"; untouched routing\n"},
        {"name":"TEST_SPEC.ini","text":"; original definitions\n"}
    ]);
    serde_json::json!({
        "comparison":comparison,
        "review":null,
        "template_pack":null,
        "flow_anchor":"; INSERT TX HERE\n"
    })
}

#[cfg(feature = "mcp")]
async fn compose_report(arguments: serde_json::Value) -> Result<serde_json::Value> {
    compose_report_with_snapshot(arguments, tx_plan_snapshot()).await
}

#[cfg(feature = "mcp")]
async fn compose_report_with_snapshot(
    arguments: serde_json::Value,
    snapshot: Snapshot,
) -> Result<serde_json::Value> {
    let server =
        script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(CompositionCatalog(snapshot)));
    let request = serde_json::from_value(arguments)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let result = server
        .compose_ini_bundle(rmcp::handler::server::wrapper::Parameters(request))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing composition result".into()))
}

#[cfg(feature = "mcp")]
struct CompositionCatalog(Snapshot);

#[cfg(feature = "mcp")]
impl script_audit_mcp::Catalog for CompositionCatalog {
    fn snapshot(&self) -> Result<Snapshot> {
        Ok(self.0.clone())
    }
}

#[cfg(feature = "mcp")]
async fn wifi_comparison_report(arguments: serde_json::Value) -> Result<serde_json::Value> {
    let server = script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(CompositionCatalog(
        wifi_composition_snapshot(),
    )));
    let request = serde_json::from_value(arguments)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let result = server
        .compare_plan_to_bundle(rmcp::handler::server::wrapper::Parameters(request))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing comparison result".into()))
}

#[cfg(feature = "mcp")]
async fn reviewed_composition_arguments() -> Result<serde_json::Value> {
    let mut arguments = compose_bundle_arguments();
    for file in arguments["comparison"]["bundle"]["files"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing fixture files".into()))?
    {
        file["text"] = format!(
            "; SYNTHETIC FIXTURE ONLY\n{}",
            file["text"].as_str().unwrap_or("")
        )
        .into();
    }
    arguments["comparison"]["bundle"]["files"][0]["text"] = concat!(
        "; SYNTHETIC FIXTURE ONLY\r\n; keep order and CRLF\r\n",
        "[TEST FLOW:Normal]\r\n; INSERT TX HERE\r\n",
        "; alternate stays inactive\r\n; historical checksum: original-unverified\r\n; Password=synthetic-secret\r\n"
    ).into();
    arguments["flow_anchor"] = "; INSERT TX HERE\r\n".into();
    arguments["comparison"]["bundle"]["files"][2]["text"] = concat!(
        "; SYNTHETIC FIXTURE ONLY\n[STATION]\n",
        "Equipment=synthetic\nRoute=synthetic-route\nTimeout=1\nSupport=synthetic.dat\n",
        "Password=synthetic-secret\n"
    )
    .into();
    arguments["station_settings"] = serde_json::json!([
        {"role":"equipment","file":"FACTORY_SETTING.ini","section":"STATION","key":"Equipment"},
        {"role":"routing","file":"FACTORY_SETTING.ini","section":"STATION","key":"Route"},
        {"role":"timing","file":"FACTORY_SETTING.ini","section":"STATION","key":"Timeout"},
        {"role":"support_file","file":"FACTORY_SETTING.ini","section":"STATION","key":"Support"},
        {"role":"credential","file":"FACTORY_SETTING.ini","section":"STATION","key":"Password"}
    ]);
    arguments["template_pack"] =
        serde_json::from_str(include_str!("fixtures/reviewed-tx-template.json"))
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    bind_composition_review(arguments).await
}

#[cfg(feature = "mcp")]
async fn bind_composition_review(mut arguments: serde_json::Value) -> Result<serde_json::Value> {
    let preview = compose_report(arguments.clone()).await?;
    let approval = |identity: &serde_json::Value| {
        serde_json::json!({
            "subject_identity":identity,
            "approver":"synthetic-reviewer",
            "evidence":"SYNTHETIC ONLY - not station approval",
            "kind":"synthetic_fixture"
        })
    };
    arguments["review"] = serde_json::json!({
        "plan":approval(&preview["input_identities"]["plan"]),
        "base":approval(&preview["input_identities"]["base"]),
        "settings":approval(&preview["input_identities"]["settings"])
    });
    arguments["template_pack"]["approval"] =
        approval(&preview["input_identities"]["template_pack"]);
    if let Some(items) = arguments
        .get_mut("procedure_templates")
        .and_then(serde_json::Value::as_array_mut)
    {
        for item in items {
            let id = item["requirement_id"].as_str().unwrap_or("").to_string();
            item["template_pack"]["approval"] =
                approval(&preview["input_identities"]["procedures"][&id]);
        }
    }
    Ok(arguments)
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_draft_approval_is_separate_from_input_review_and_readiness() -> Result<()> {
    let arguments = reviewed_composition_arguments().await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(report["draft_approval"]["status"], "not_supplied");
    assert_eq!(
        report["draft_approval"]["authority"],
        "client_verification_required"
    );
    assert_eq!(report["export"], "not_performed");
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(report["artifact_authority"], "synthetic_only");
    assert_eq!(report["runtime_verification"], "unchecked");
    assert_eq!(report["hardware_verification"], "unchecked");
    assert_eq!(report["packaging"], "unchecked");
    assert_eq!(report["checksum"], "not_refreshed");
    assert_eq!(compose_report(arguments).await?, report);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_draft_approval_records_only_current_complete_operator_claims() -> Result<()> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    for pointer in [
        "/review/plan/kind",
        "/review/base/kind",
        "/review/settings/kind",
        "/template_pack/approval/kind",
    ] {
        *arguments.pointer_mut(pointer).ok_or_else(|| {
            script_audit_mcp::Error::Knowledge("missing fixture approval".into())
        })? = "operator_review".into();
    }
    let preview = compose_report(arguments.clone()).await?;
    assert_eq!(preview["status"], "valid", "{preview}");
    assert_eq!(preview["ready_for_review"], true);
    assert_eq!(preview["draft_approval"]["status"], "not_supplied");
    let approval = json!({"subject_identity":preview["draft_identity"],
        "approver":"fixture-reviewer", "evidence":"Fixture claim only; no physical export authorized",
        "kind":"operator_review"});
    for (field, value, expected) in [
        ("evidence", json!(""), "incomplete_evidence"),
        ("approver", json!(" \t"), "incomplete_evidence"),
        ("subject_identity", json!("sha256:old-draft"), "stale"),
        ("kind", json!("synthetic_fixture"), "blocked"),
        ("evidence", approval["evidence"].clone(), "recorded_claim"),
    ] {
        let mut submitted = arguments.clone();
        submitted["draft_approval"] = approval.clone();
        submitted["draft_approval"][field] = value;
        let report = compose_report(submitted).await?;
        assert_eq!(report["draft_approval"]["status"], expected);
        assert_eq!(report["draft_identity"], preview["draft_identity"]);
        assert_eq!(report["ready_for_review"], true);
        assert_eq!(report["draft_files"], preview["draft_files"]);
        assert_eq!(report["export"], "not_performed");
        assert_eq!(
            report["draft_approval"]["authority"],
            "client_verification_required"
        );
    }
    arguments["draft_approval"] = approval;
    arguments["review"]["base"]["kind"] = "synthetic_fixture".into();
    let blocked_preview = compose_report(arguments.clone()).await?;
    arguments["draft_approval"]["subject_identity"] = blocked_preview["draft_identity"].clone();
    let blocked = compose_report(arguments).await?;
    assert_eq!(blocked["ready_for_review"], false);
    assert_eq!(blocked["draft_approval"]["status"], "blocked");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_draft_approval_is_stale_after_each_bound_input_or_content_change() -> Result<()> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["plan"]["exceptions"] = json!([]);
    arguments["procedure_templates"] = json!([procedure_pack(
        "TX-OFDM6",
        "DLLWIFI_TEST",
        "TX_MULTI_VERIFICATION"
    )]);
    let mut arguments = bind_composition_review(arguments).await?;
    let baseline = compose_report(arguments.clone()).await?;
    arguments["draft_approval"] = json!({"subject_identity":baseline["draft_identity"],
        "approver":"fixture-reviewer", "evidence":"Fixture only", "kind":"operator_review"});
    let claimed = compose_report(arguments.clone()).await?;
    assert_eq!(claimed["draft_approval"]["status"], "blocked");
    let mut metadata = arguments.clone();
    metadata["report_metadata"] = json!({"request_id":"new", "timestamp":"incidental"});
    assert_eq!(compose_report(metadata).await?, claimed);
    let mut reordered = tx_plan_snapshot();
    reordered.functions.reverse();
    reordered.parameter_definitions.reverse();
    reordered.parameter_links.reverse();
    reordered.criteria_definitions.reverse();
    reordered.criteria_links.reverse();
    assert_eq!(
        compose_report_with_snapshot(arguments.clone(), reordered).await?,
        claimed
    );
    for (path, replacement) in [
        ("/comparison/plan/sources/0/revision", json!("3.9")),
        (
            "/comparison/plan/requirements/0/test/power_target/value",
            json!(18),
        ),
        (
            "/comparison/plan/exceptions",
            json!([{
                "id":"fixture-exception", "conflict_id":"fixture-conflict", "requirement_id":"TX-OFDM6",
                "station":"HH5K Wireless Test_2", "source_revisions":{"plan":"3.8"},
                "decision":arguments["comparison"]["plan"]["requirements"][0]["test"],
                "rationale":"Synthetic decision only", "approver":"fixture-reviewer", "approval_evidence":"fixture only"
            }]),
        ),
        (
            "/comparison/bundle/files/3/text",
            json!("; SYNTHETIC FIXTURE ONLY\n; changed draft bytes\n"),
        ),
        (
            "/comparison/bundle/files/2/text",
            json!(
                "; SYNTHETIC FIXTURE ONLY\n[STATION]\nEquipment=new\nRoute=synthetic-route\nTimeout=1\nSupport=synthetic.dat\nPassword=synthetic-secret\n"
            ),
        ),
        ("/station_settings/0/key", json!("Route")),
        ("/template_pack/version", json!("2")),
        ("/procedure_templates/0/template_pack/version", json!("2")),
        (
            "/comparison/bundle/selected_flow",
            json!("[TEST FLOW:Sampling]"),
        ),
        ("/comparison/flow_variant", json!("sampling")),
        ("/flow_anchor", json!("; NEW ANCHOR\r\n")),
    ] {
        let mut changed = arguments.clone();
        *changed.pointer_mut(path).ok_or_else(|| {
            script_audit_mcp::Error::Knowledge(format!("missing fixture path {path}"))
        })? = replacement;
        let report = compose_report(bind_composition_review(changed).await?).await?;
        assert_ne!(
            report["draft_identity"], baseline["draft_identity"],
            "{path}"
        );
        assert_eq!(report["draft_approval"]["status"], "stale", "{path}");
        assert_eq!(report["export"], "not_performed");
    }
    let mut changed_catalog = tx_plan_snapshot();
    changed_catalog.parameter_definitions[0].default_value =
        Some("unapplied fixture default".into());
    let report = compose_report_with_snapshot(arguments, changed_catalog).await?;
    assert_ne!(
        report["input_identities"]["catalog"],
        baseline["input_identities"]["catalog"]
    );
    assert_eq!(report["draft_files"], baseline["draft_files"]);
    assert_eq!(report["draft_approval"]["status"], "stale");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_draft_approval_cannot_clear_conflicts_sampling_or_invalidity() -> Result<()> {
    use serde_json::json;
    let mut conflicts = reviewed_composition_arguments().await?;
    conflicts["comparison"]["plan"] = tx_conflict_arguments()["plan"].clone();
    let sampling = sampling_matrix_arguments("sampling").await?;
    let mut invalid = reviewed_composition_arguments().await?;
    invalid["comparison"]["bundle"]["files"][1]["text"] =
        "; SYNTHETIC FIXTURE ONLY\n[BROKEN]\nROW=\"unterminated\n".into();
    for (arguments, blocker, expected_status) in [
        (conflicts, "conflict", "invalid"),
        (sampling, "sampling", "incomplete"),
        (invalid, "", "invalid"),
    ] {
        let mut arguments = bind_composition_review(arguments).await?;
        let baseline =
            compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
        arguments["draft_approval"] = json!({"subject_identity":baseline["draft_identity"],
            "approver":"fixture-reviewer", "evidence":"Not operational approval", "kind":"operator_review"});
        let report = compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
        assert_eq!(report["status"], expected_status, "{blocker}: {report}");
        assert_eq!(report["draft_approval"]["status"], "blocked");
        assert_eq!(report["ready_for_review"], false);
        assert_eq!(report["blockers"], baseline["blockers"]);
        assert!(
            report["blockers"]
                .to_string()
                .to_lowercase()
                .contains(blocker)
        );
        assert_eq!(report["comparison"], baseline["comparison"]);
        assert_eq!(report["draft_files"], baseline["draft_files"]);
        assert_eq!(report["export"], "not_performed");
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_draft_approval_redacts_claim_text_without_corrupting_identity_or_states()
-> Result<()> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["bundle"]["sensitive_values"] = json!([
        "blocked",
        "client_verification_required",
        "sha256:",
        "synthetic-secret"
    ]);
    let mut arguments = bind_composition_review(arguments).await?;
    let preview = compose_report(arguments.clone()).await?;
    arguments["draft_approval"] = json!({"subject_identity":preview["draft_identity"],
        "approver":"synthetic-secret", "evidence":"client_verification_required blocked synthetic-secret",
        "kind":"operator_review"});
    let report = compose_report(arguments).await?;
    assert_eq!(report["draft_approval"]["status"], "blocked");
    assert_eq!(
        report["draft_approval"]["authority"],
        "client_verification_required"
    );
    assert_eq!(
        report["draft_approval"]["claim"]["subject_identity"],
        preview["draft_identity"]
    );
    assert_eq!(report["draft_approval"]["claim"]["approver"], "[REDACTED]");
    assert_eq!(
        report["draft_approval"]["claim"]["evidence"],
        "[REDACTED] [REDACTED] [REDACTED]"
    );
    assert!(!report["diffs"].to_string().contains("synthetic-secret"));
    assert!(
        !report["historical_footers"]
            .to_string()
            .contains("synthetic-secret")
    );
    assert_eq!(report["draft_files"], preview["draft_files"]);
    assert!(
        report["draft_files"]
            .to_string()
            .contains("synthetic-secret")
    );
    Ok(())
}

#[cfg(feature = "mcp")]
fn procedure_pack(id: &str, device: &str, function: &str) -> serde_json::Value {
    let text = format!(
        "[{{{{section}}}}]\nMEASURE=\"{device}|{function}|{{{{parameters}}}}|{{{{criteria}}}}|*V:STATION-Timeout#|NEXT|FAIL|\"\n"
    );
    serde_json::json!({"requirement_id":id,"template_pack":{
        "id":format!("synthetic-{id}"),"version":"1",
        "source":{"name":format!("{id}-source.ini"),"text":text},
        "corrected":{"name":format!("{id}-reviewed.ini"),"text":text},
        "corrections":[],"approval":null
    }})
}

#[cfg(feature = "mcp")]
async fn wifi_lifecycle_arguments() -> Result<serde_json::Value> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    let mut requirements = calibration_plan_arguments()["plan"]["requirements"]
        .as_array()
        .ok_or_else(|| {
            script_audit_mcp::Error::Knowledge("missing calibration requirements".into())
        })?
        .clone();
    requirements[1]["test"]["bandwidth"] = json!({"value":160,"unit":"MHz"});
    let mut tx = arguments["comparison"]["plan"]["requirements"][0].clone();
    tx["depends_on"] = json!(["CAL"]);
    requirements.push(tx);
    for (id, purpose, function, parameters, dependencies) in [
        (
            "SAVE",
            "save",
            "SENDSTR",
            "fixture@save",
            json!(["RX-MCS7", "TX-OFDM6"]),
        ),
        (
            "CLEANUP",
            "cleanup",
            "CLOSE",
            "fixture@close",
            json!(["SAVE"]),
        ),
    ] {
        requirements.push(json!({"id":id,"applicability":"mandatory","depends_on":dependencies,
            "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"Synthetic lifecycle requirement"}],
            "test":{"purpose":purpose,"procedure":{"device":"SSH","function":function,"parameters":parameters,"criteria":"NULL"}}}));
    }
    arguments["comparison"]["plan"]["requirements"] = requirements.into();
    arguments["procedure_templates"] = json!([
        procedure_pack("RX-MCS7", "DLLWIFI_TEST", "RX_VERIFY_PER"),
        procedure_pack("CAL", "DLLWIFI_TEST", "BRCM_RSSI_CALIBRATION"),
        procedure_pack("SETUP", "SSH", "OPEN"),
        procedure_pack("SAVE", "SSH", "SENDSTR"),
        procedure_pack("CLEANUP", "SSH", "CLOSE")
    ]);
    bind_composition_review(arguments).await
}

#[cfg(feature = "mcp")]
async fn bluetooth_composition_arguments() -> Result<serde_json::Value> {
    use serde_json::json;
    let mut arguments = wifi_lifecycle_arguments().await?;
    let bluetooth = bluetooth_rx_arguments();
    for requirement in bluetooth["plan"]["requirements"]
        .as_array()
        .ok_or_else(|| {
            script_audit_mcp::Error::Knowledge("missing Bluetooth requirements".into())
        })?
    {
        let id = requirement["id"].as_str().unwrap_or("");
        let function = match requirement["test"]["purpose"].as_str().unwrap_or("") {
            "setup" => "DUT_INSERT",
            "tx" => "TX_MULTI_VERIFY",
            "rx" => "RX_VERIFY_PER",
            _ => unreachable!(),
        };
        arguments["comparison"]["plan"]["requirements"]
            .as_array_mut()
            .ok_or_else(|| {
                script_audit_mcp::Error::Knowledge("missing combined requirements".into())
            })?
            .push(requirement.clone());
        arguments["procedure_templates"]
            .as_array_mut()
            .ok_or_else(|| {
                script_audit_mcp::Error::Knowledge("missing procedure templates".into())
            })?
            .push(procedure_pack(id, "DLLIOT", function));
    }
    arguments["comparison"]["plan"]["requirements"][4]["depends_on"] = json!([
        "RX-MCS7",
        "TX-OFDM6",
        "BT-TX-2404",
        "BT-TX-2480",
        "BT-RX-2404",
        "BT-RX-2480"
    ]);
    bind_composition_review(arguments).await
}

#[cfg(feature = "mcp")]
async fn sampling_matrix_arguments(variant: &str) -> Result<serde_json::Value> {
    use serde_json::json;
    let mut arguments = bluetooth_composition_arguments().await?;
    arguments["comparison"]["flow_variant"] = json!(variant);
    let selected = if variant == "sampling" {
        "[TEST FLOW:Sampling]"
    } else {
        "[TEST FLOW:Normal]"
    };
    arguments["comparison"]["bundle"]["selected_flow"] = json!(selected);
    arguments["comparison"]["bundle"]["files"][0]["text"] =
        arguments["comparison"]["bundle"]["files"][0]["text"]
            .as_str()
            .unwrap_or("")
            .replace("[TEST FLOW:Normal]", selected)
            .into();
    arguments["comparison"]["plan"]["requirements"][0]["test"]["standard"] = json!("11AX");
    arguments["comparison"]["plan"]["requirements"][0]["test"]["bandwidth"] =
        json!({"value":160,"unit":"MHz"});
    arguments["comparison"]["plan"]["requirements"][0]["test"]["frequency"] =
        json!({"value":6345,"unit":"MHz"});
    let tx = arguments["comparison"]["plan"]["requirements"][3].clone();
    let rx = arguments["comparison"]["plan"]["requirements"][0].clone();
    for (purpose, standard, bandwidth, rate, channel, frequency, applicability) in [
        ("tx", "11AX", 160, "MCS11", 47, 6185, "mandatory"),
        ("tx", "11AX", 160, "MCS11", 175, 6825, "mandatory"),
        ("tx", "11BE", 320, "MCS0", 191, 6905, "mandatory"),
        ("tx", "11BE", 320, "MCS13", 63, 6265, "mandatory"),
        ("tx", "11AX", 160, "MCS11", 15, 6025, "sampling"),
        ("tx", "11AX", 160, "MCS11", 79, 6345, "sampling"),
        ("tx", "11AX", 160, "MCS11", 111, 6505, "sampling"),
        ("tx", "11AX", 160, "MCS11", 143, 6665, "sampling"),
        ("tx", "11AX", 160, "MCS11", 207, 6985, "sampling"),
        ("tx", "11BE", 320, "MCS0", 31, 6105, "sampling"),
        ("tx", "11BE", 320, "MCS13", 159, 6745, "sampling"),
        ("rx", "11AX", 160, "MCS7", 143, 6665, "mandatory"),
        ("rx", "11BE", 320, "MCS7", 63, 6265, "mandatory"),
        ("rx", "11AX", 160, "MCS7", 15, 6025, "sampling"),
        ("rx", "11AX", 160, "MCS7", 47, 6185, "sampling"),
        ("rx", "11AX", 160, "MCS7", 111, 6505, "sampling"),
        ("rx", "11AX", 160, "MCS7", 175, 6825, "sampling"),
        ("rx", "11AX", 160, "MCS7", 207, 6985, "sampling"),
        ("rx", "11BE", 320, "MCS7", 127, 6585, "sampling"),
        ("rx", "11BE", 320, "MCS7", 159, 6745, "sampling"),
    ] {
        let id = format!("{purpose}-{standard}-{rate}-CH{channel}");
        let mut requirement = if purpose == "tx" {
            tx.clone()
        } else {
            rx.clone()
        };
        requirement["id"] = json!(id);
        requirement["applicability"] = json!(applicability);
        requirement["test"]["standard"] = json!(standard);
        requirement["test"]["bandwidth"] = json!({"value":bandwidth,"unit":"MHz"});
        requirement["test"]["frequency"] = json!({"value":frequency,"unit":"MHz"});
        requirement["test"]["rate"] = json!(rate);
        requirement["provenance"] = json!([{"source_id":"plan","revision":"3.8",
            "location":"section 6.5, pages 28-34, synthetic transcription fixture",
            "excerpt":format!("{applicability} {standard} {bandwidth} MHz {purpose} {rate} CH{channel}; explicit {frequency} MHz fixture; not production approval")}]);
        arguments["comparison"]["plan"]["requirements"]
            .as_array_mut()
            .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing requirements".into()))?
            .insert(4, requirement);
        if purpose == "rx" {
            arguments["procedure_templates"]
                .as_array_mut()
                .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing templates".into()))?
                .push(procedure_pack(&id, "DLLWIFI_TEST", "RX_VERIFY_PER"));
        }
    }
    bind_composition_review(arguments).await
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn client_workflow_reviews_sources_resolves_scoped_conflicts_and_rejects_stale_handoff()
-> Result<()> {
    use serde_json::json;
    for source_mode in ["document", "prompt", "combined"] {
        for (variant, sampling_count) in [("normal", 0), ("sampling", 14)] {
            let mut arguments = sampling_matrix_arguments(variant).await?;
            let source_kind = if source_mode == "prompt" {
                "prompt"
            } else {
                "test_plan"
            };
            arguments["comparison"]["plan"]["sources"] = json!([
                {"id":"plan","revision":"3.8","kind":source_kind,"approved":true}
            ]);
            if source_mode == "combined" {
                arguments["comparison"]["plan"]["sources"] = json!([
                    {"id":"plan","revision":"3.8","kind":"test_plan","approved":true},
                    {"id":"prompt","revision":"fixture-1","kind":"prompt","approved":true}
                ]);
                arguments["comparison"]["plan"]["requirements"][3]["provenance"]
                    .as_array_mut()
                    .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing provenance".into()))?
                    .push(json!({"source_id":"prompt","revision":"fixture-1",
                        "excerpt":"Synthetic prompt confirms supplied OFDM6 limits; not station approval."}));
            }
            let bluetooth = bluetooth_conflict_arguments();
            arguments["comparison"]["plan"]["conflicts"] = json!([
                bluetooth["plan"]["conflicts"][0],
                bluetooth["plan"]["conflicts"][1]
            ]);
            arguments["comparison"]["plan"]["sampling_policy"] = json!({
                "rate":{"value":5,"unit":"%"},"schedule":"SYNTHETIC ONLY: operator selection each shift",
                "provenance":[{"source_id":"plan","revision":"3.8",
                    "excerpt":"Fixture-only policy; no audited scheduler application or production approval."}]
            });
            arguments = bind_composition_review(arguments).await?;
            let before = wifi_comparison_report(arguments["comparison"].clone()).await?;
            assert_eq!(before["ready_for_review"], false);
            assert_eq!(before["conflicts"][0]["resolved_by"], json!(null));
            assert_eq!(before["conflicts"][1]["resolved_by"], json!(null));
            let unresolved =
                compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot())
                    .await?;
            assert_eq!(unresolved["status"], "invalid", "{source_mode}/{variant}");
            assert_eq!(
                unresolved["comparison"]["conflicts"][0]["resolved_by"],
                json!(null)
            );
            assert_eq!(
                unresolved["comparison"]["conflicts"][1]["resolved_by"],
                json!(null)
            );
            assert_eq!(unresolved["draft_files"].as_array().map(Vec::len), Some(6));
            assert_eq!(unresolved["ready_for_review"], false);

            arguments["comparison"]["plan"]["exceptions"] =
                json!([bluetooth_exception(&bluetooth, 0, 0)]);
            arguments = bind_composition_review(arguments).await?;
            let scoped =
                compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot())
                    .await?;
            assert_eq!(
                scoped["comparison"]["conflicts"][0]["resolved_by"],
                "synthetic-BT-approval-0"
            );
            assert_eq!(
                scoped["comparison"]["conflicts"][1]["resolved_by"],
                json!(null)
            );
            assert_eq!(scoped["ready_for_review"], false);

            arguments["comparison"]["plan"]["exceptions"] = json!([
                bluetooth_exception(&bluetooth, 0, 0),
                bluetooth_exception(&bluetooth, 1, 1)
            ]);
            arguments = bind_composition_review(arguments).await?;
            let report =
                compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot())
                    .await?;
            assert_eq!(report["status"], "incomplete", "{}", report["blockers"]);
            assert_eq!(report["artifact_authority"], "synthetic_only");
            assert_eq!(report["comparison"]["validation"]["status"], "valid");
            assert_eq!(
                report["comparison"]["interpretation_verification"],
                "unchecked_client_interpretation"
            );
            assert_eq!(
                report["comparison"]["mandatory"],
                json!({"total":17,"matched":17})
            );
            assert_eq!(
                report["comparison"]["sampling"],
                json!({"total":sampling_count,"matched":sampling_count})
            );
            for identity in [
                &report["input_identities"]["plan"],
                &report["draft_identity"],
            ] {
                assert!(
                    identity
                        .as_str()
                        .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71)
                );
            }
            assert_ne!(report["draft_identity"], unresolved["draft_identity"]);
            assert_eq!(report["diffs"].as_array().map(Vec::len), Some(2));
            assert_eq!(report["ready_for_review"], false);
            if variant == "sampling" {
                assert_eq!(report["sampling_policy"]["status"], "sourced_requirements");
                assert_eq!(
                    report["sampling_policy"]["runtime_application"],
                    "unchecked_not_encoded"
                );
                assert!(report["blockers"].to_string().contains("application"));
            }
            let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
            let limits = report["draft_files"][5]["text"].as_str().unwrap_or("");
            for expected in [
                "STANDARD=11AG&FREQ=6115&BW=20&DATA_RATE=OFDM6&TX_TARGET_POWER=*V:",
                "DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2404&",
                "DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2480&",
                "DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2404&",
                "DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2480&",
            ] {
                assert!(
                    main.contains(expected),
                    "{source_mode}/{variant}: {expected}"
                );
            }
            assert_eq!(
                main.contains("STANDARD=11AX&FREQ=6025&BW=160&DATA_RATE=MCS11&"),
                variant == "sampling"
            );
            for expected in [
                "TARGET=15.5dBm\nPOWER=-1~2dB\nEVM=<-35dB",
                "INPUT=-60dBm\nPER=<10%\nRSSI=-6~6dB",
                "TARGET=20\nPOWER=-3~1\nOFFSET=-150~150",
                "INPUT=-87\nPER=<30.8%",
            ] {
                assert!(limits.contains(expected), "{expected}");
            }
            let mut comparison = arguments["comparison"].clone();
            comparison["bundle"]["files"] = report["draft_files"].clone();
            let checked = wifi_comparison_report(comparison.clone()).await?;
            assert_eq!(checked["mandatory"], json!({"total":17,"matched":17}));
            assert_eq!(
                checked["sampling"],
                json!({"total":sampling_count,"matched":sampling_count})
            );
            for coverage in checked["coverage"].as_array().ok_or_else(|| {
                script_audit_mcp::Error::Knowledge("missing workflow coverage".into())
            })? {
                assert_eq!(coverage["status"], "matched");
                assert!(
                    coverage["provenance"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty())
                );
                assert!(
                    coverage["evidence"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty())
                );
            }
            comparison["bundle"]["files"][0]["text"] =
                main.replace("FREQ=2404", "FREQ=2405").into();
            let changed = wifi_comparison_report(comparison).await?;
            assert!(
                changed["mandatory"]["matched"]
                    .as_u64()
                    .is_some_and(|count| count < 17)
            );

            arguments["draft_approval"] = json!({"subject_identity":report["draft_identity"],
                "approver":"synthetic-reviewer","evidence":"SYNTHETIC ONLY - no export consent",
                "kind":"synthetic_fixture"});
            let claimed =
                compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot())
                    .await?;
            assert_eq!(claimed["draft_approval"]["status"], "blocked");
            assert_eq!(
                claimed["draft_approval"]["authority"],
                "client_verification_required"
            );
            assert_eq!(claimed["draft_files"], report["draft_files"]);
            assert_eq!(claimed["draft_identity"], report["draft_identity"]);
            arguments["comparison"]["plan"]["unresolved_questions"] = json!([
                "Synthetic source changed: human must inspect table/figure before handoff."
            ]);
            let stale =
                compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
            assert_eq!(stale["draft_approval"]["status"], "stale");
            assert_ne!(stale["draft_identity"], report["draft_identity"]);
            assert_eq!(stale["ready_for_review"], false);
            for result in [&unresolved, &scoped, &report, &claimed, &stale] {
                assert_eq!(result["export"], "not_performed");
                assert_eq!(result["checksum"], "not_refreshed");
                for field in ["runtime_verification", "hardware_verification", "packaging"] {
                    assert_eq!(result[field], "unchecked");
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn client_workflow_supporting_sources_cannot_replace_controlling_authority() -> Result<()> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["plan"]["sources"] = json!([
        {"id":"plan","revision":"3.8","kind":"test_plan","approved":true},
        {"id":"prompt","revision":"fixture-1","kind":"prompt","approved":true}
    ]);
    let supporting = json!({"source_id":"prompt","revision":"fixture-1",
        "excerpt":"SYNTHETIC ONLY: confirm controlling plan limits."});
    arguments["comparison"]["plan"]["requirements"][0]["provenance"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing provenance".into()))?
        .push(supporting.clone());
    arguments = bind_composition_review(arguments).await?;
    let baseline = compose_report(arguments.clone()).await?;
    assert_eq!(
        baseline["comparison"]["mandatory"],
        json!({"total":1,"matched":1})
    );
    for case in [
        "missing_controlling",
        "stale_support",
        "unapproved_support",
        "example_support",
        "blank_support",
        "unknown_support",
    ] {
        let mut changed = arguments.clone();
        match case {
            "missing_controlling" => {
                changed["comparison"]["plan"]["requirements"][0]["provenance"] = json!([supporting])
            }
            "stale_support" => {
                changed["comparison"]["plan"]["requirements"][0]["provenance"][1]["revision"] =
                    json!("fixture-0")
            }
            "unapproved_support" => {
                changed["comparison"]["plan"]["sources"][1]["approved"] = json!(false)
            }
            "example_support" => {
                changed["comparison"]["plan"]["sources"][1]["kind"] = json!("example")
            }
            "blank_support" => {
                changed["comparison"]["plan"]["requirements"][0]["provenance"][1]["excerpt"] =
                    json!("")
            }
            _ => {
                changed["comparison"]["plan"]["requirements"][0]["provenance"][1]["source_id"] =
                    json!("unsupplied")
            }
        }
        let mut comparison = changed["comparison"].clone();
        comparison["bundle"]["files"] = baseline["draft_files"].clone();
        let checked = wifi_comparison_report(comparison).await?;
        assert_eq!(
            checked["mandatory"],
            json!({"total":1,"matched":0}),
            "{case}"
        );
        assert!(
            checked["coverage"][0]["reasons"]
                .to_string()
                .contains("controlling-source provenance"),
            "{case}"
        );
        assert_eq!(checked["ready_for_review"], false);
        let changed = bind_composition_review(changed).await?;
        let report = compose_report(changed.clone()).await?;
        assert_eq!(
            report["draft_files"], changed["comparison"]["bundle"]["files"],
            "{case}"
        );
        assert_eq!(report["diffs"], json!([]), "{case}");
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_matrix_independently_verifies_both_flows_and_revalidation() -> Result<()>
{
    use serde_json::json;
    for (variant, sampling_count) in [("normal", 0), ("sampling", 14)] {
        let arguments = sampling_matrix_arguments(variant).await?;
        let report =
            compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
        assert_eq!(
            report["comparison"]["mandatory"],
            json!({"total":17,"matched":17}),
            "{}",
            report["blockers"]
        );
        assert_eq!(
            report["comparison"]["sampling"],
            json!({"total":sampling_count,"matched":sampling_count}),
            "{}",
            report["blockers"]
        );
        assert_eq!(report["comparison"]["validation"]["status"], "valid");
        let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
        for expected in [
            "STANDARD=11AG&FREQ=6115&BW=20&DATA_RATE=OFDM6&",
            "STANDARD=11AX&FREQ=6185&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11AX&FREQ=6825&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11BE&FREQ=6905&BW=320&DATA_RATE=MCS0&",
            "STANDARD=11BE&FREQ=6265&BW=320&DATA_RATE=MCS13&",
            "STANDARD=11AX&FREQ=6345&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11AX&FREQ=6665&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11BE&FREQ=6265&BW=320&DATA_RATE=MCS7&",
            "DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2404&",
            "DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2480&",
            "DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2404&",
            "DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2480&",
        ] {
            assert!(main.contains(expected), "{variant}: {expected}");
        }
        for expected in [
            "STANDARD=11AX&FREQ=6025&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11AX&FREQ=6345&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11AX&FREQ=6505&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11AX&FREQ=6665&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11AX&FREQ=6985&BW=160&DATA_RATE=MCS11&",
            "STANDARD=11BE&FREQ=6105&BW=320&DATA_RATE=MCS0&",
            "STANDARD=11BE&FREQ=6745&BW=320&DATA_RATE=MCS13&",
            "STANDARD=11AX&FREQ=6025&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11AX&FREQ=6185&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11AX&FREQ=6505&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11AX&FREQ=6825&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11AX&FREQ=6985&BW=160&DATA_RATE=MCS7&",
            "STANDARD=11BE&FREQ=6585&BW=320&DATA_RATE=MCS7&",
            "STANDARD=11BE&FREQ=6745&BW=320&DATA_RATE=MCS7&",
        ] {
            assert_eq!(
                main.contains(expected),
                variant == "sampling",
                "{variant}: {expected}"
            );
        }
        let definitions = report["draft_files"][5]["text"].as_str().unwrap_or("");
        assert_eq!(
            definitions
                .matches("INPUT=-60dBm\nPER=<10%\nRSSI=-6~6dB\n")
                .count(),
            if variant == "sampling" { 10 } else { 3 }
        );
        assert_eq!(
            main.matches("&FRAME_COUNT=500").count(),
            if variant == "sampling" { 24 } else { 10 }
        );
        let mut comparison = arguments["comparison"].clone();
        comparison["bundle"]["files"] = report["draft_files"].clone();
        let checked = wifi_comparison_report(comparison).await?;
        assert_eq!(checked["mandatory"], report["comparison"]["mandatory"]);
        assert_eq!(checked["sampling"], report["comparison"]["sampling"]);
        let repeated = compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
        assert_eq!(report, repeated);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_missing_policy_blocks_readiness_without_inventing_values() -> Result<()> {
    let arguments = sampling_matrix_arguments("sampling").await?;
    let report = compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
    assert!(
        report["blockers"]
            .to_string()
            .contains("sampling rate and schedule"),
        "{}",
        report["blockers"]
    );
    assert_eq!(report["comparison"]["mandatory"]["matched"], 17);
    assert_eq!(report["comparison"]["sampling"]["matched"], 14);
    assert_eq!(report["sampling_policy"]["status"], "unresolved");
    assert_eq!(
        report["sampling_policy"]["requirements"],
        serde_json::Value::Null
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_sampling_requires_policy_and_audited_application_despite_full_coverage() -> Result<()>
{
    use serde_json::json;
    let arguments = sampling_matrix_arguments("sampling").await?;
    let generated =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    for (policy, status, blocker) in [
        (
            json!({"rate":{"value":5,"unit":"%"},"schedule":"synthetic shift",
            "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"synthetic policy"}]}),
            "sourced_requirements",
            "application",
        ),
        (json!(null), "unresolved", "sampling rate and schedule"),
        (
            json!({"rate":{"value":0,"unit":"%"},"schedule":"synthetic shift",
            "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"synthetic policy"}]}),
            "unresolved",
            "sampling rate and schedule",
        ),
        (
            json!({"rate":{"value":5,"unit":"%"},"schedule":"synthetic shift",
            "provenance":[{"source_id":"plan","revision":"3.7","excerpt":"stale policy"}]}),
            "unresolved",
            "sampling rate and schedule",
        ),
    ] {
        let mut comparison = arguments["comparison"].clone();
        comparison["bundle"]["files"] = generated["draft_files"].clone();
        comparison["plan"]["sampling_policy"] = policy;
        let report = wifi_comparison_report(comparison).await?;
        assert_eq!(report["mandatory"], json!({"total":17,"matched":17}));
        assert_eq!(report["sampling"], json!({"total":14,"matched":14}));
        assert_eq!(report["ready_for_review"], false, "{report}");
        assert_eq!(report["sampling_policy"]["status"], status);
        assert!(report["blockers"].to_string().contains(blocker));
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_sourced_policy_is_review_bound_and_never_becomes_engine_settings()
-> Result<()> {
    use serde_json::json;
    let mut arguments = sampling_matrix_arguments("sampling").await?;
    let without_policy =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    let policy = json!({"rate":{"value":5.0,"unit":"%"},"schedule":"Synthetic operator selection each shift",
        "provenance":[{"source_id":"plan","revision":"3.8","location":"synthetic sampling policy appendix","excerpt":"Fixture-only 5 percent policy; not production approval"}]});
    arguments["comparison"]["plan"]["sampling_policy"] = policy.clone();
    let stale =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert!(
        stale["blockers"]
            .to_string()
            .contains("Current reviewed plan identity")
    );
    assert_ne!(stale["draft_identity"], without_policy["draft_identity"]);
    let arguments = bind_composition_review(arguments).await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(report["sampling_policy"]["status"], "sourced_requirements");
    assert_eq!(report["sampling_policy"]["requirements"], policy);
    assert_eq!(
        report["sampling_policy"]["runtime_application"],
        "unchecked_not_encoded"
    );
    assert!(report["blockers"].to_string().contains("application"));
    assert_eq!(report["draft_files"], without_policy["draft_files"]);
    assert!(
        !report["blockers"]
            .to_string()
            .contains("sampling rate and schedule")
    );
    assert_eq!(report["artifact_authority"], "synthetic_only");
    assert_eq!(report["ready_for_review"], false);
    let mut normal = arguments;
    normal["comparison"]["flow_variant"] = json!("normal");
    let normal = bind_composition_review(normal).await?;
    let report = compose_report_with_snapshot(normal, wifi_composition_snapshot()).await?;
    assert_eq!(report["sampling_policy"]["status"], "not_applicable");
    assert_eq!(
        report["comparison"]["sampling"],
        json!({"total":0,"matched":0})
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_revalidation_rejects_omissions_wrong_channels_and_false_witnesses()
-> Result<()> {
    use serde_json::json;
    let arguments = sampling_matrix_arguments("sampling").await?;
    let generated =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    let cases = generated["comparison"]["coverage"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing coverage".into()))?;
    let case = cases
        .iter()
        .find(|case| case["requirement_id"] == "tx-11AX-MCS11-CH47")
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing mandatory case".into()))?;
    let section = case["evidence"][0]["section"]
        .as_str()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing evidence section".into()))?;
    let main = generated["draft_files"][0]["text"].as_str().unwrap_or("");
    let row = main
        .lines()
        .find(|line| line.contains("STANDARD=11AX&FREQ=6185&BW=160&DATA_RATE=MCS11&"))
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing mandatory row".into()))?;
    let entry = format!("{section}=\"{section}\"\r\n");
    assert_eq!(main.matches(&entry).count(), 1);
    for (mutation, changed) in [
        ("removed", main.replace(row, "")),
        ("commented", main.replace(row, &format!(";{row}"))),
        ("unreachable", main.replace(&entry, &format!(";{entry}"))),
        (
            "wrong_channel_same_label",
            main.replace(row, &row.replace("FREQ=6185", "FREQ=6205")),
        ),
        (
            "extra_does_not_substitute",
            main.replace(
                row,
                &row.replace("FREQ=6185", "FREQ=6205")
                    .replace("DATA_RATE=MCS11", "DATA_RATE=MCS9"),
            ),
        ),
        (
            "sampling_replaces_mandatory",
            main.replace(row, &row.replace("FREQ=6185", "FREQ=6025")),
        ),
        (
            "unknown",
            main.replace(row, &row.replace("FREQ=6185", "FREQ=*E:CHANNEL#")),
        ),
    ] {
        let mut comparison = arguments["comparison"].clone();
        comparison["bundle"]["files"] = generated["draft_files"].clone();
        comparison["bundle"]["files"][0]["text"] = json!(changed);
        let report = wifi_comparison_report(comparison).await?;
        let case = report["coverage"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["requirement_id"] == "tx-11AX-MCS11-CH47")
            })
            .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing mutated case".into()))?;
        assert_ne!(case["status"], "matched", "{mutation}: {report}");
        assert!(
            report["mandatory"]["matched"]
                .as_u64()
                .is_some_and(|count| count < 17),
            "{mutation}"
        );
        assert_eq!(
            report["sampling"],
            json!({"total":14,"matched":14}),
            "{mutation}"
        );
        assert_eq!(report["ready_for_review"], false, "{mutation}");
        if mutation == "extra_does_not_substitute" {
            assert!(
                report["additional"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
            );
        }
    }
    let mut comparison = arguments["comparison"].clone();
    comparison["bundle"]["files"] = generated["draft_files"].clone();
    comparison["bundle"]["selected_flow"] = json!("[TEST FLOW:Normal]");
    let report = wifi_comparison_report(comparison).await?;
    assert_eq!(report["mandatory"]["matched"], 0);
    assert_eq!(report["sampling"]["matched"], 0);
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_rejects_unsourced_invalid_or_incomplete_policy() -> Result<()> {
    use serde_json::json;
    let arguments = sampling_matrix_arguments("sampling").await?;
    for (field, value) in [
        ("rate", json!(null)),
        ("rate", json!({"value":0,"unit":"%"})),
        ("rate", json!({"value":101,"unit":"%"})),
        ("rate", json!({"value":5,"unit":"units"})),
        ("schedule", json!(null)),
        ("schedule", json!(" ")),
        ("provenance", json!([])),
        (
            "provenance",
            json!([{"source_id":"plan","revision":"stale","excerpt":"not current"}]),
        ),
        (
            "provenance",
            json!([{"source_id":"example","revision":"3.8","excerpt":"not controlling"}]),
        ),
        ("provenance", json!([{"source_id":"plan","revision":"3.8"}])),
    ] {
        let mut invalid = arguments.clone();
        invalid["comparison"]["plan"]["sampling_policy"] = json!({
            "rate":{"value":5,"unit":"%"},"schedule":"synthetic shift selection",
            "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"Synthetic approved fixture policy"}]
        });
        invalid["comparison"]["plan"]["sampling_policy"][field] = value;
        let invalid = bind_composition_review(invalid).await?;
        let report = compose_report_with_snapshot(invalid, wifi_composition_snapshot()).await?;
        assert_eq!(
            report["sampling_policy"]["status"], "unresolved",
            "{field}: {report}"
        );
        assert!(
            report["blockers"]
                .to_string()
                .contains("sampling rate and schedule")
        );
        assert_eq!(report["ready_for_review"], false);
        assert_eq!(report["comparison"]["sampling"]["matched"], 14);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_preserves_unresolved_source_conflicts_and_stale_exceptions() -> Result<()>
{
    use serde_json::json;
    let mut arguments = sampling_matrix_arguments("sampling").await?;
    let bluetooth = bluetooth_conflict_arguments();
    let wifi = tx_conflict_arguments();
    arguments["comparison"]["plan"]["sources"] = wifi["plan"]["sources"].clone();
    let mut conflicts = bluetooth["plan"]["conflicts"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing BT conflicts".into()))?
        .clone();
    conflicts.push(wifi["plan"]["conflicts"][0].clone());
    arguments["comparison"]["plan"]["conflicts"] = json!(conflicts);
    let mut stale = bluetooth_exception(&bluetooth, 0, 0);
    stale["source_revisions"]["plan"] = json!("3.7");
    arguments["comparison"]["plan"]["exceptions"] = json!([stale]);
    let report = compose_report_with_snapshot(
        bind_composition_review(arguments).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_eq!(
        report["comparison"]["conflicts"].as_array().map(Vec::len),
        Some(4)
    );
    for index in 0..4 {
        assert_eq!(
            report["comparison"]["conflicts"][index]["resolved_by"],
            serde_json::Value::Null
        );
        for field in ["id", "requirement_id", "kind"] {
            assert_eq!(
                report["comparison"]["conflicts"][index]["conflict"][field],
                conflicts[index][field]
            );
        }
        for statement in 0..2 {
            assert_eq!(
                report["comparison"]["conflicts"][index]["conflict"]["statements"][statement]["provenance"],
                conflicts[index]["statements"][statement]["provenance"]
            );
        }
    }
    assert_eq!(
        report["comparison"]["conflicts"][0]["conflict"]["statements"][0]["test"]["channel"],
        0
    );
    assert_eq!(
        report["comparison"]["conflicts"][1]["conflict"]["statements"][0]["test"]["channel"],
        78
    );
    assert_eq!(
        report["comparison"]["conflicts"][3]["conflict"]["statements"][1]["test"]["power_target"]["value"],
        18.0
    );
    assert_eq!(report["comparison"]["sampling"]["matched"], 14);
    assert!(
        report["comparison"]["mandatory"]["matched"]
            .as_u64()
            .is_some_and(|count| count < 17)
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_preserves_base_bytes_redacted_diffs_links_and_operational_gates()
-> Result<()> {
    let arguments = sampling_matrix_arguments("sampling").await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    for index in 1..5 {
        assert_eq!(
            report["draft_files"][index],
            arguments["comparison"]["bundle"]["files"][index]
        );
    }
    for index in [0, 5] {
        let mut remaining = report["draft_files"][index]["text"].as_str().unwrap_or("");
        for original in arguments["comparison"]["bundle"]["files"][index]["text"]
            .as_str()
            .unwrap_or("")
            .split_inclusive('\n')
        {
            let position = remaining.find(original).ok_or_else(|| {
                script_audit_mcp::Error::Knowledge("original bytes missing or reordered".into())
            })?;
            remaining = &remaining[position + original.len()..];
        }
    }
    let diffs = report["diffs"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing diffs".into()))?;
    assert_eq!(diffs.len(), 2);
    assert!(
        report["draft_files"]
            .to_string()
            .contains("synthetic-secret")
    );
    let mut summary = report.clone();
    summary
        .as_object_mut()
        .map(|fields| fields.remove("draft_files"));
    summary["comparison"]["validation"]["source_files"] = serde_json::Value::Null;
    assert!(!summary.to_string().contains("synthetic-secret"));
    assert!(
        diffs
            .iter()
            .all(|diff| diff["format"] == "whole_file_unified")
    );
    let links = report["limit_links"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing limit links".into()))?;
    assert_eq!(links.len(), 76);
    for link in links {
        assert!(
            report["draft_files"][0]["text"]
                .as_str()
                .unwrap_or("")
                .contains(link["reference"].as_str().unwrap_or("MISSING"))
        );
    }
    for field in ["runtime_verification", "hardware_verification", "packaging"] {
        assert_eq!(report[field], "unchecked");
    }
    assert_eq!(report["export"], "not_performed");
    assert_eq!(report["checksum"], "not_refreshed");
    assert_eq!(
        report["historical_footers"][0]["verification"],
        "unverified_for_changed_content"
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_redaction_preserves_policy_states_but_redacts_supplied_policy_text()
-> Result<()> {
    use serde_json::json;
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["flow_variant"] = json!("sampling");
    arguments["comparison"]["bundle"]["sensitive_values"] = json!(["unchecked"]);
    arguments["comparison"]["plan"]["sampling_policy"] = json!({
        "rate":{"value":5,"unit":"%"},"schedule":"Synthetic unchecked schedule",
        "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"Synthetic unchecked policy"}]
    });
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    for policy in [
        &report["sampling_policy"],
        &report["comparison"]["sampling_policy"],
    ] {
        assert_eq!(policy["runtime_application"], "unchecked_not_encoded");
        assert_eq!(policy["status"], "sourced_requirements");
        assert!(!policy["requirements"].to_string().contains("unchecked"));
        assert!(policy["requirements"].to_string().contains("[REDACTED]"));
    }
    let mut comparison = arguments["comparison"].clone();
    comparison["bundle"]["files"] = report["draft_files"].clone();
    let checked = plan_report(comparison).await?;
    assert_eq!(
        checked["sampling_policy"]["runtime_application"],
        "unchecked_not_encoded"
    );
    assert_eq!(checked["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_sampling_retains_mandatory_wifi_and_bluetooth_coverage() -> Result<()> {
    use serde_json::json;
    let mut arguments = bluetooth_composition_arguments().await?;
    arguments["comparison"]["flow_variant"] = json!("sampling");
    arguments["comparison"]["bundle"]["selected_flow"] = json!("[TEST FLOW:Sampling]");
    let main = arguments["comparison"]["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or("")
        .replace("[TEST FLOW:Normal]", "[TEST FLOW:Sampling]");
    arguments["comparison"]["bundle"]["files"][0]["text"] = main.into();
    let mut sampling = arguments["comparison"]["plan"]["requirements"][3].clone();
    sampling["id"] = json!("TX-AX160-CH15-SAMPLING");
    sampling["applicability"] = json!("sampling");
    sampling["test"]["standard"] = json!("11AX");
    sampling["test"]["rate"] = json!("MCS11");
    sampling["test"]["frequency"] = json!({"value":6025,"unit":"MHz"});
    sampling["test"]["bandwidth"] = json!({"value":160,"unit":"MHz"});
    arguments["comparison"]["plan"]["requirements"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing requirements".into()))?
        .push(sampling);
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
    assert_eq!(
        report["comparison"]["mandatory"],
        json!({"total":11,"matched":11}),
        "{}",
        report["blockers"]
    );
    assert_eq!(
        report["comparison"]["sampling"],
        json!({"total":1,"matched":1}),
        "{}",
        report["blockers"]
    );
    assert_eq!(report["comparison"]["validation"]["status"], "valid");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_retains_wifi_and_sourced_limits_in_successful_lifecycle() -> Result<()> {
    let arguments = bluetooth_composition_arguments().await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(
        report["comparison"]["mandatory"],
        serde_json::json!({"total":11,"matched":11}),
        "{}",
        report["blockers"]
    );
    let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
    let definitions = report["draft_files"][5]["text"].as_str().unwrap_or("");
    assert!(main.contains("DLLIOT|DUT_INSERT|TECH=BT&DUT_NAME=fixture&DUT_CASE=fixture|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    for (index, frequency) in [(6, 2404), (7, 2480)] {
        assert!(main.contains(&format!("DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ={frequency}&TX_TARGET_POWER=*V:BT_DRAFT_{index}-TARGET#|POWER=*V:BT_DRAFT_{index}-POWER#&FREQ_ERROR_KHZ=*V:BT_DRAFT_{index}-OFFSET#|*V:STATION-Timeout#|NEXT|FAIL|")), "{main}");
        assert!(
            definitions.contains(&format!(
                "[BT_DRAFT_{index}]\nTARGET=20\nPOWER=-3~1\nOFFSET=-150~150\n"
            )),
            "{definitions}"
        );
    }
    for (index, frequency) in [(9, 2404), (10, 2480)] {
        assert!(main.contains(&format!("DLLIOT|RX_VERIFY_PER|ANT=1&FREQ={frequency}&RX_TARGET_POWER=*V:BT_DRAFT_{index}-INPUT#&FRAME_COUNT=500|PER=*V:BT_DRAFT_{index}-PER#|*V:STATION-Timeout#|NEXT|FAIL|")), "{main}");
        assert!(
            definitions.contains(&format!("[BT_DRAFT_{index}]\nINPUT=-87\nPER=<30.8%\n")),
            "{definitions}"
        );
    }
    assert!(main.contains("BRCM_RSSI_CALIBRATION"));
    assert!(main.contains("TX_MULTI_VERIFICATION"));
    assert!(main.contains("SSH|SENDSTR|fixture@save"));
    assert!(main.contains("SSH|CLOSE|fixture@close"));
    assert_eq!(
        report["comparison"]["validation"]["status"], "valid",
        "{report}"
    );
    assert!(
        !report["blockers"]
            .to_string()
            .contains("Bluetooth composition remains unsupported")
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_revalidation_rejects_changed_limits_frequencies_and_omissions()
-> Result<()> {
    let arguments = bluetooth_composition_arguments().await?;
    let generated =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    let mut comparison = arguments["comparison"].clone();
    comparison["bundle"]["files"] = generated["draft_files"].clone();
    for (file, before, after, requirement) in [
        (
            0,
            "ANT=1&FREQ=2404&TX_TARGET",
            "ANT=1&FREQ=2402&TX_TARGET",
            6,
        ),
        (5, "TARGET=20\nPOWER=-3~1", "TARGET=18\nPOWER=-3~1", 6),
        (5, "POWER=-3~1", "POWER=-3~2", 6),
        (5, "OFFSET=-150~150", "OFFSET=-149~150", 6),
        (5, "OFFSET=-150~150", "OFFSET=-150~151", 6),
        (5, "INPUT=-87", "INPUT=-86", 9),
        (5, "PER=<30.8%", "PER=<=30.8%", 9),
        (5, "PER=<30.8%", "PER=30.8%", 9),
        (
            0,
            "FRAME_COUNT=500|PER=*V:BT_DRAFT_9",
            "FRAME_COUNT=499|PER=*V:BT_DRAFT_9",
            9,
        ),
        (
            0,
            "BT_DRAFT_10=\"BT_DRAFT_10\"",
            ";BT_DRAFT_10=\"BT_DRAFT_10\"",
            10,
        ),
        (0, "TECH=BT&DUT_NAME", "TECH=ZIGBEE&DUT_NAME", 6),
        (
            0,
            "DUT_CASE=fixture|NULL|*V:STATION-Timeout#|NEXT|FAIL|",
            "DUT_CASE=fixture|NULL|*V:STATION-Timeout#|NEXT|NEXT|",
            6,
        ),
    ] {
        let mut changed = comparison.clone();
        let text = changed["bundle"]["files"][file]["text"]
            .as_str()
            .unwrap_or("");
        assert!(text.contains(before), "missing mutation anchor {before}");
        changed["bundle"]["files"][file]["text"] = text.replace(before, after).into();
        let report = wifi_comparison_report(changed).await?;
        assert_ne!(
            report["coverage"][requirement]["status"], "matched",
            "{before} -> {after}"
        );
        assert_eq!(report["mandatory"]["total"], 11);
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_preserves_conflicts_and_consumes_only_current_specific_exceptions()
-> Result<()> {
    use serde_json::json;
    let baseline = bluetooth_composition_arguments().await?;
    let conflict_plan = bluetooth_conflict_arguments();
    let exceptions: Vec<_> = [(0, 0), (1, 1), (2, 0)]
        .into_iter()
        .map(|(conflict, requirement)| bluetooth_exception(&conflict_plan, conflict, requirement))
        .collect();
    for case in [
        "unresolved",
        "partial",
        "stale",
        "wrong_requirement",
        "missing_evidence",
        "approved",
        "channel_only",
    ] {
        let mut arguments = baseline.clone();
        arguments["comparison"]["plan"]["conflicts"] = conflict_plan["plan"]["conflicts"].clone();
        arguments["comparison"]["plan"]["exceptions"] = match case {
            "unresolved" => json!([]),
            "partial" => json!([exceptions[0]]),
            _ => json!(exceptions),
        };
        match case {
            "stale" => {
                arguments["comparison"]["plan"]["exceptions"][0]["source_revisions"]["plan"] =
                    "3.7".into()
            }
            "wrong_requirement" => {
                arguments["comparison"]["plan"]["exceptions"][0]["requirement_id"] =
                    "BT-TX-2480".into()
            }
            "missing_evidence" => {
                arguments["comparison"]["plan"]["exceptions"][0]["approval_evidence"] = "".into()
            }
            "channel_only" => {
                arguments["comparison"]["plan"]["exceptions"][0]["decision"] =
                    conflict_plan["plan"]["conflicts"][0]["statements"][0]["test"].clone()
            }
            _ => (),
        }
        let arguments = bind_composition_review(arguments).await?;
        let report =
            compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
        let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
        assert!(main.contains("[TX_DRAFT_3]"), "{case}");
        assert!(main.contains("[BT_DRAFT_9]"), "{case}");
        for conflict in 0..3 {
            for field in ["id", "kind", "requirement_id"] {
                assert_eq!(
                    report["comparison"]["conflicts"][conflict]["conflict"][field],
                    conflict_plan["plan"]["conflicts"][conflict][field]
                );
            }
            for statement in 0..2 {
                assert_eq!(
                    report["comparison"]["conflicts"][conflict]["conflict"]["statements"]
                        [statement]["provenance"],
                    conflict_plan["plan"]["conflicts"][conflict]["statements"][statement]["provenance"]
                );
            }
        }
        assert_eq!(
            report["comparison"]["conflicts"][0]["conflict"]["statements"][0]["test"]["channel"],
            0
        );
        assert_eq!(
            report["comparison"]["conflicts"][1]["conflict"]["statements"][0]["test"]["channel"],
            78
        );
        if case == "approved" {
            assert_eq!(
                report["comparison"]["mandatory"]["matched"], 11,
                "{}",
                report["blockers"]
            );
            assert!(main.contains("[BT_DRAFT_6]"));
            assert!(main.contains("[BT_DRAFT_7]"));
        } else {
            assert!(!main.contains("[BT_DRAFT_6]"), "{case}");
            assert!(
                report["comparison"]["mandatory"]["matched"]
                    .as_u64()
                    .is_some_and(|count| count < 11)
            );
        }
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_requires_current_templates_station_settings_and_scoped_catalog()
-> Result<()> {
    use serde_json::json;
    let baseline = bluetooth_composition_arguments().await?;
    for case in [
        "missing_template",
        "stale_template",
        "template_question",
        "wrong_timing",
        "unsupported_catalog",
        "orphan_definition",
        "missing_default",
        "wrong_scope",
        "missing_routing",
        "missing_support",
    ] {
        let mut arguments = baseline.clone();
        let mut snapshot = wifi_composition_snapshot();
        match case {
            "missing_template" => {
                arguments["procedure_templates"]
                    .as_array_mut()
                    .ok_or_else(|| {
                        script_audit_mcp::Error::Knowledge("missing procedure templates".into())
                    })?
                    .remove(5);
            }
            "stale_template" => {
                arguments["procedure_templates"][5]["template_pack"]["version"] = "2".into()
            }
            "template_question" => {
                arguments["procedure_templates"][5]["template_pack"]["unresolved_questions"] =
                    json!(["BT template requires engineering review"]);
                arguments = bind_composition_review(arguments).await?;
            }
            "wrong_timing" => {
                for field in ["source", "corrected"] {
                    arguments["procedure_templates"][5]["template_pack"][field]["text"] = arguments
                        ["procedure_templates"][5]["template_pack"][field]["text"]
                        .as_str()
                        .unwrap_or("")
                        .replace("*V:STATION-Timeout#", "100000")
                        .into();
                }
                arguments = bind_composition_review(arguments).await?;
            }
            "unsupported_catalog" => snapshot.functions.retain(|function| {
                function.interface != "IOT" || function.name != "TX_MULTI_VERIFY"
            }),
            "orphan_definition" => snapshot.criteria_definitions.retain(|definition| {
                definition.device_name != "IOT" || definition.name != "FREQ_ERROR_KHZ"
            }),
            "missing_default" => {
                snapshot.parameter_definitions.push(Definition {
                    name: "REQUIRED_ROUTE".into(),
                    device_name: "IOT".into(),
                    kind: "string".into(),
                    cardinality: "SINGLE".into(),
                    value_pattern: "<value>".into(),
                    default_value: Some("never-insert".into()),
                    ..Definition::default()
                });
                snapshot.parameter_links.push(Link {
                    name: "REQUIRED_ROUTE".into(),
                    function_source: "DLL".into(),
                    function_name: "TX_MULTI_VERIFY".into(),
                    device_name: "IOT".into(),
                    required: true,
                    position: None,
                });
            }
            "wrong_scope" => {
                arguments["comparison"]["bundle"]["device_scope"] = "OTHER-STATION".into()
            }
            "missing_routing" | "missing_support" => {
                arguments["station_settings"][if case == "missing_routing" { 1 } else { 3 }]["key"] =
                    "UNSUPPLIED".into();
                arguments = bind_composition_review(arguments).await?;
            }
            _ => unreachable!(),
        }
        let report = compose_report_with_snapshot(arguments.clone(), snapshot).await?;
        let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
        assert!(!main.contains("[BT_DRAFT_6]"), "{case}");
        assert!(!main.contains("never-insert"));
        if matches!(case, "missing_routing" | "missing_support") {
            assert_eq!(
                report["draft_files"],
                arguments["comparison"]["bundle"]["files"]
            );
        } else if case != "wrong_scope" {
            assert!(main.contains("[TX_DRAFT_3]"), "{case}");
            assert!(main.contains("[BT_DRAFT_9]"), "{case}");
        }
        assert!(
            report["blockers"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{case}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_direct_macro_preserves_arguments_and_failure_returns() -> Result<()> {
    let mut arguments = bluetooth_composition_arguments().await?;
    arguments["procedure_templates"][5] = procedure_pack("BT-TX-2404", "MACRO", "BT_TX_BODY");
    arguments["comparison"]["bundle"]["files"][1]["text"] = concat!(
        "; SYNTHETIC FIXTURE ONLY\n; reviewed macro retained\n[BT_TX_BODY]\n",
        "TX=\"DLLIOT|TX_MULTI_VERIFY|ANT=*V:Macro-Param_ANT#&FREQ=*V:Macro-Param_FREQ#&TX_TARGET_POWER=*V:Macro-Param_TX_TARGET_POWER#|POWER=*V:Macro-Criteria_POWER#&FREQ_ERROR_KHZ=*V:Macro-Criteria_FREQ_ERROR_KHZ#|*V:STATION-Timeout#|PASS|FAIL|\"\n"
    ).into();
    let arguments = bind_composition_review(arguments).await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(
        report["comparison"]["mandatory"]["matched"], 11,
        "{}",
        report["blockers"]
    );
    assert!(report["comparison"]["coverage"][6]["evidence"][0]["call_site"].is_string());
    assert_eq!(
        report["draft_files"][1],
        arguments["comparison"]["bundle"]["files"][1]
    );
    let mut failed = arguments;
    failed["comparison"]["bundle"]["files"][1]["text"] = failed["comparison"]["bundle"]["files"][1]
        ["text"]
        .as_str()
        .unwrap_or("")
        .replace("|PASS|FAIL|", "|PASS|PASS|")
        .into();
    let report = compose_report_with_snapshot(
        bind_composition_review(failed).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_ne!(report["comparison"]["coverage"][4]["status"], "matched");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_is_deterministic_preserves_base_and_redacts_complete_diffs() -> Result<()>
{
    let arguments = bluetooth_composition_arguments().await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?,
        report
    );
    for file in 1..5 {
        assert_eq!(
            report["draft_files"][file],
            arguments["comparison"]["bundle"]["files"][file]
        );
    }
    assert_eq!(report["diffs"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["limit_links"].as_array().map(Vec::len), Some(16));
    for (id, section, keys) in [
        (
            "BT-TX-2404",
            "BT_DRAFT_6",
            vec!["TARGET", "POWER", "OFFSET"],
        ),
        (
            "BT-TX-2480",
            "BT_DRAFT_7",
            vec!["TARGET", "POWER", "OFFSET"],
        ),
        ("BT-RX-2404", "BT_DRAFT_9", vec!["INPUT", "PER"]),
        ("BT-RX-2480", "BT_DRAFT_10", vec!["INPUT", "PER"]),
    ] {
        for key in keys {
            assert!(
                report["limit_links"]
                    .as_array()
                    .is_some_and(|links| links.iter().any(|link| link["requirement_id"] == id
                        && link["definition"]["section"] == section
                        && link["definition"]["key"] == key
                        && link["definition"]["file"] == "TEST_SPEC.ini"
                        && link["usage"]["row"] == "MEASURE"
                        && link["reference"] == format!("*V:{section}-{key}#")))
            );
        }
    }
    assert!(
        report["draft_files"][0]["text"]
            .as_str()
            .unwrap_or("")
            .starts_with("; SYNTHETIC FIXTURE ONLY\r\n; keep order and CRLF\r\n")
    );
    assert!(
        report["diffs"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("TX_MULTI_VERIFY")
    );
    let mut review = report.clone();
    review["draft_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["source_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["script_sections"] = serde_json::Value::Null;
    assert!(!review.to_string().contains("synthetic-secret"));
    for key in ["runtime_verification", "hardware_verification", "packaging"] {
        assert_eq!(report[key], "unchecked");
    }
    assert_eq!(report["checksum"], "not_refreshed");
    assert_eq!(report["export"], "not_performed");
    assert_eq!(report["artifact_authority"], "synthetic_only");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_never_guesses_missing_units_channels_or_measurement_dimensions()
-> Result<()> {
    use serde_json::json;
    let baseline = bluetooth_composition_arguments().await?;
    for (requirement, field, value) in [
        (6, "frequency", json!({"value":2404,"unit":"kHz"})),
        (6, "frequency", json!(null)),
        (6, "channel", json!(0)),
        (6, "bandwidth", json!({"value":2,"unit":"MHz"})),
        (6, "power_target", json!({"value":20,"unit":"dB"})),
        (
            6,
            "power_tolerance",
            json!({"lower":-3,"upper":1,"unit":"dBm"}),
        ),
        (
            6,
            "frequency_offset",
            json!({"lower":-150,"upper":150,"unit":"Hz"}),
        ),
        (6, "frequency_offset", json!(null)),
        (6, "chains", json!({"kind":"count","value":1})),
        (9, "packet_count", json!(null)),
        (9, "input_level", json!({"value":-87,"unit":"dB"})),
        (
            9,
            "per",
            json!({"operator":"le","threshold":{"value":30.8,"unit":"%"}}),
        ),
    ] {
        let mut arguments = baseline.clone();
        arguments["comparison"]["plan"]["requirements"][requirement]["test"][field] = value;
        let report = compose_report_with_snapshot(
            bind_composition_review(arguments).await?,
            wifi_composition_snapshot(),
        )
        .await?;
        let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
        assert!(
            !main.contains(&format!("[BT_DRAFT_{requirement}]")),
            "{requirement}: {field}"
        );
        assert!(main.contains("[TX_DRAFT_3]"));
        assert_eq!(report["comparison"]["mandatory"]["total"], 11);
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_bluetooth_tagged_save_cleanup_revalidate_without_weakening_setup() -> Result<()> {
    let mut arguments = bluetooth_composition_arguments().await?;
    for index in [4, 5] {
        arguments["comparison"]["plan"]["requirements"][index]["test"]["technology"] =
            "bluetooth".into();
    }
    let arguments = bind_composition_review(arguments).await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(
        report["comparison"]["mandatory"]["matched"], 11,
        "{}",
        report["blockers"]
    );
    assert_eq!(report["comparison"]["coverage"][4]["status"], "matched");
    assert_eq!(report["comparison"]["coverage"][5]["status"], "matched");
    let mut comparison = arguments["comparison"].clone();
    comparison["bundle"]["files"] = report["draft_files"].clone();
    for (before, after, requirement) in [
        ("TECH=BT&DUT_NAME", "TECH=ZIGBEE&DUT_NAME", 6),
        (
            "fixture@save|NULL|*V:STATION-Timeout#|NEXT|FAIL|",
            "fixture@save|NULL|*V:STATION-Timeout#|NEXT|NEXT|",
            5,
        ),
    ] {
        let mut changed = comparison.clone();
        let text = changed["bundle"]["files"][0]["text"].as_str().unwrap_or("");
        assert!(text.contains(before));
        changed["bundle"]["files"][0]["text"] = text.replace(before, after).into();
        let report = wifi_comparison_report(changed).await?;
        assert_ne!(
            report["coverage"][requirement]["status"], "matched",
            "{before}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_lifecycle_follows_successful_dependencies_not_plan_list_order() -> Result<()>
{
    let arguments = wifi_lifecycle_arguments().await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(
        report["comparison"]["mandatory"],
        serde_json::json!({"total":6,"matched":6}),
        "{report}"
    );
    let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
    assert!(
        main.contains(concat!(
            "WIFI_DRAFT_2=\"WIFI_DRAFT_2\"\r\nWIFI_DRAFT_1=\"WIFI_DRAFT_1\"\r\n",
            "WIFI_DRAFT_0=\"WIFI_DRAFT_0\"\r\nTX_DRAFT_3=\"TX_DRAFT_3\"\r\n",
            "WIFI_DRAFT_4=\"WIFI_DRAFT_4\"\r\nWIFI_DRAFT_5=\"WIFI_DRAFT_5\"\r\n"
        )),
        "{main}"
    );
    assert!(main.contains("BRCM_RSSI_CALIBRATION|BAND=6G&ANT=1,2,4,8&STANDARD=11AX&BW=160|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    assert!(main.contains("SSH|OPEN|fixture@fixture-host|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    assert!(main.contains("SSH|SENDSTR|fixture@save|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    assert!(main.contains("SSH|CLOSE|fixture@close|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    assert_eq!(
        report["comparison"]["validation"]["status"], "valid",
        "{report}"
    );
    assert!(
        !report["blockers"]
            .to_string()
            .contains("Bluetooth composition remains unsupported")
    );
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(report["export"], "not_performed");
    assert_eq!(
        compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?,
        report
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_calibration_without_limits_preserves_unterminated_spec_bytes() -> Result<()> {
    let mut arguments = wifi_lifecycle_arguments().await?;
    let mut calibration = arguments["comparison"]["plan"]["requirements"][1].clone();
    calibration["depends_on"] = serde_json::json!([]);
    arguments["comparison"]["plan"]["requirements"] = serde_json::json!([calibration]);
    arguments["procedure_templates"] = serde_json::json!([procedure_pack(
        "CAL",
        "DLLWIFI_TEST",
        "BRCM_RSSI_CALIBRATION"
    )]);
    arguments["comparison"]["bundle"]["files"][5]["text"] =
        "; SYNTHETIC FIXTURE ONLY\n[KEEP]\nValue=original".into();
    let report = compose_report_with_snapshot(
        bind_composition_review(arguments.clone()).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_eq!(report["comparison"]["mandatory"]["matched"], 1);
    assert_eq!(
        report["draft_files"][5],
        arguments["comparison"]["bundle"]["files"][5]
    );
    assert_eq!(report["diffs"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["limit_links"], serde_json::json!([]));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_revalidation_rejects_independent_limit_and_order_mutations() -> Result<()> {
    let arguments = wifi_lifecycle_arguments().await?;
    let generated =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    let mut comparison = arguments["comparison"].clone();
    comparison["bundle"]["files"] = generated["draft_files"].clone();
    for (file, before, after, case) in [
        (0, "FRAME_COUNT=500|PER=", "FRAME_COUNT=499|PER=", 0),
        (5, "PER=<10%", "PER=<=10%", 0),
        (
            0,
            "RX_VERIFY_PER|BAND=6G&ANT=1,2,4,8",
            "RX_VERIFY_PER|BAND=6G&ANT=1,2,4",
            0,
        ),
        (
            0,
            "WIFI_DRAFT_2=\"WIFI_DRAFT_2\"\r\nWIFI_DRAFT_1=\"WIFI_DRAFT_1\"",
            "WIFI_DRAFT_1=\"WIFI_DRAFT_1\"\r\nWIFI_DRAFT_2=\"WIFI_DRAFT_2\"",
            1,
        ),
        (0, "STANDARD=11AX&BW=160", "STANDARD=11BE&BW=160", 1),
        (0, "STANDARD=11AX&BW=160", "STANDARD=11AX&BW=320", 1),
        (
            0,
            "fixture@fixture-host|NULL|*V:STATION-Timeout#|NEXT|FAIL|",
            "fixture@fixture-host|NULL|*V:STATION-Timeout#|NEXT|NEXT|",
            0,
        ),
    ] {
        let mut changed = comparison.clone();
        let text = changed["bundle"]["files"][file]["text"]
            .as_str()
            .unwrap_or("");
        assert!(text.contains(before), "missing mutation anchor {before}");
        changed["bundle"]["files"][file]["text"] = text.replace(before, after).into();
        let report = wifi_comparison_report(changed).await?;
        assert_ne!(
            report["coverage"][case]["status"], "matched",
            "{before} -> {after}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_missing_or_unapproved_templates_preserve_available_tx_and_base() -> Result<()>
{
    let baseline = wifi_lifecycle_arguments().await?;
    for (index, change) in [
        (0, "missing"),
        (1, "unapproved"),
        (1, "stale"),
        (0, "timing"),
        (1, "question"),
        (0, "macro"),
    ] {
        let mut arguments = baseline.clone();
        match change {
            "missing" => {
                arguments["procedure_templates"]
                    .as_array_mut()
                    .ok_or_else(|| {
                        script_audit_mcp::Error::Knowledge("missing procedure templates".into())
                    })?
                    .remove(index);
            }
            "unapproved" => {
                arguments["procedure_templates"][index]["template_pack"]["approval"] =
                    serde_json::Value::Null
            }
            "stale" => {
                arguments["procedure_templates"][index]["template_pack"]["version"] = "2".into()
            }
            "timing" => {
                for field in ["source", "corrected"] {
                    arguments["procedure_templates"][index]["template_pack"][field]["text"] =
                        arguments["procedure_templates"][index]["template_pack"][field]["text"]
                            .as_str()
                            .unwrap_or("")
                            .replace("*V:STATION-Timeout#", "20000")
                            .into();
                }
                arguments = bind_composition_review(arguments).await?;
            }
            "question" => {
                arguments["procedure_templates"][index]["template_pack"]["unresolved_questions"] =
                    serde_json::json!(["Unapproved calibration repair"]);
                arguments = bind_composition_review(arguments).await?;
            }
            "macro" => {
                arguments["procedure_templates"][index] =
                    procedure_pack("RX-MCS7", "MACRO", "UNSUPPLIED");
                arguments = bind_composition_review(arguments).await?;
            }
            _ => unreachable!(),
        }
        let report =
            compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
        let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
        assert!(main.contains("TX_MULTI_VERIFICATION"));
        assert!(!main.contains(&format!("[WIFI_DRAFT_{index}]")), "{change}");
        for file in 1..5 {
            assert_eq!(
                report["draft_files"][file],
                arguments["comparison"]["bundle"]["files"][file]
            );
        }
        assert!(
            report["blockers"]
                .to_string()
                .contains("approved RX/calibration/procedure template")
        );
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_preserves_history_uncertainty_and_requires_supplied_support_settings()
-> Result<()> {
    let mut arguments = wifi_lifecycle_arguments().await?;
    arguments["comparison"]["plan"]["requirements"][1]["test"]["calibration_interval"] =
        serde_json::json!({"value":2,"unit":"weeks"});
    arguments = bind_composition_review(arguments).await?;
    let report =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    assert_eq!(report["comparison"]["coverage"][1]["status"], "unknown");
    assert!(
        report["comparison"]["coverage"][1]["reasons"]
            .to_string()
            .contains("scheduling and calibration history remain unchecked")
    );
    assert!(
        report["draft_files"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("BRCM_RSSI_CALIBRATION")
    );
    assert_eq!(report["runtime_verification"], "unchecked");
    assert_eq!(report["hardware_verification"], "unchecked");
    arguments["station_settings"][3]["key"] = "MISSING_SUPPORT".into();
    let report = compose_report_with_snapshot(
        bind_composition_review(arguments.clone()).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert!(report["blockers"].to_string().contains("SupportFile"));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_ax160_and_be320_preserve_sourced_values_and_review_identity() -> Result<()> {
    let arguments = wifi_lifecycle_arguments().await?;
    let baseline =
        compose_report_with_snapshot(arguments.clone(), wifi_composition_snapshot()).await?;
    let mut ax = arguments.clone();
    ax["comparison"]["plan"]["requirements"][0]["test"]["standard"] = "11AX".into();
    ax["comparison"]["plan"]["requirements"][0]["test"]["bandwidth"]["value"] = 160.into();
    let report = compose_report_with_snapshot(
        bind_composition_review(ax).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_eq!(report["comparison"]["mandatory"]["matched"], 6);
    assert!(
        report["draft_files"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("STANDARD=11AX&FREQ=6105&BW=160&DATA_RATE=MCS7")
    );
    assert_ne!(report["draft_identity"], baseline["draft_identity"]);
    let mut metadata = arguments.clone();
    metadata["report_metadata"] = serde_json::json!({"note":"incidental"});
    assert_eq!(
        compose_report_with_snapshot(metadata, wifi_composition_snapshot()).await?,
        baseline
    );
    let mut review = baseline.clone();
    review["draft_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["source_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["script_sections"] = serde_json::Value::Null;
    assert!(!review.to_string().contains("synthetic-secret"));
    assert_eq!(baseline["diffs"].as_array().map(Vec::len), Some(2));
    assert_eq!(baseline["limit_links"].as_array().map(Vec::len), Some(6));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_wifi_uses_supplied_direct_macro_contract_and_success_returns() -> Result<()> {
    let mut arguments = wifi_lifecycle_arguments().await?;
    arguments["procedure_templates"][1] = procedure_pack("CAL", "MACRO", "CAL_BODY");
    arguments["comparison"]["bundle"]["files"][1]["text"] = concat!(
        "; SYNTHETIC FIXTURE ONLY\n; unchanged macro evidence\n[CAL_BODY]\n",
        "CAL=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=*V:Macro-Param_BAND#&ANT=*V:Macro-Param_ANT#&STANDARD=*V:Macro-Param_STANDARD#&BW=*V:Macro-Param_BW#|NULL|*V:STATION-Timeout#|PASS|FAIL|\"\n"
    ).into();
    let report = compose_report_with_snapshot(
        bind_composition_review(arguments.clone()).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_eq!(report["comparison"]["mandatory"]["matched"], 6, "{report}");
    assert!(report["comparison"]["coverage"][1]["evidence"][0]["call_site"].is_string());
    assert_eq!(
        report["draft_files"][1],
        arguments["comparison"]["bundle"]["files"][1]
    );
    assert!(report["draft_files"][0]["text"].as_str().unwrap_or("").contains("MACRO|CAL_BODY|BAND=6G&ANT=1,2,4,8&STANDARD=11AX&BW=160|NULL|*V:STATION-Timeout#|NEXT|FAIL|"));
    let mut failed = arguments.clone();
    failed["comparison"]["bundle"]["files"][1]["text"] = failed["comparison"]["bundle"]["files"][1]
        ["text"]
        .as_str()
        .unwrap_or("")
        .replace("|PASS|FAIL|", "|PASS|PASS|")
        .into();
    let failed = compose_report_with_snapshot(
        bind_composition_review(failed).await?,
        wifi_composition_snapshot(),
    )
    .await?;
    assert_ne!(failed["comparison"]["coverage"][0]["status"], "matched");
    assert_eq!(failed["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_rx_uses_reviewed_limits_and_retains_tx() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    let rx = rx_plan_arguments()["plan"]["requirements"][0].clone();
    arguments["comparison"]["plan"]["requirements"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing TX requirements".into()))?
        .push(rx);
    let pack = serde_json::json!({
        "id":"synthetic-rx", "version":"1",
        "source":{"name":"rx-source.ini","text":"[{{section}}]\nMEASURE=\"DLLWIFI_TEST|RX_VERIFY_PER|{{parameters}}|{{criteria}}|*V:STATION-Timeout#|NEXT|FAIL|\"\n"},
        "corrected":{"name":"rx-reviewed.ini","text":"[{{section}}]\nMEASURE=\"DLLWIFI_TEST|RX_VERIFY_PER|{{parameters}}|{{criteria}}|*V:STATION-Timeout#|NEXT|FAIL|\"\n"},
        "corrections":[], "approval":null
    });
    arguments["procedure_templates"] = serde_json::json!([
        {"requirement_id":"RX-MCS7", "template_pack":pack}
    ]);
    let preview = compose_report(arguments.clone()).await?;
    arguments["procedure_templates"][0]["template_pack"]["approval"] = serde_json::json!({
        "subject_identity":preview["input_identities"]["procedures"]["RX-MCS7"],
        "approver":"synthetic-reviewer", "evidence":"SYNTHETIC ONLY", "kind":"synthetic_fixture"
    });
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report_with_snapshot(arguments, wifi_composition_snapshot()).await?;
    let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
    assert!(main.contains("RX_VERIFY_PER|BAND=6G&ANT=1,2,4,8&STANDARD=11BE&FREQ=6105&BW=320&DATA_RATE=MCS7&RX_TARGET_POWER=*V:WIFI_DRAFT_1-INPUT#&FRAME_COUNT=500|PER=*V:WIFI_DRAFT_1-PER#&RSSI=*V:WIFI_DRAFT_1-RSSI#"), "{report}");
    assert!(
        report["draft_files"][5]["text"]
            .as_str()
            .unwrap_or("")
            .contains("[WIFI_DRAFT_1]\nINPUT=-60dBm\nPER=<10%\nRSSI=-6~6dB\n")
    );
    assert_eq!(report["comparison"]["mandatory"]["matched"], 2, "{report}");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
fn wifi_composition_snapshot() -> Snapshot {
    let mut snapshot = tx_plan_snapshot();
    add_bluetooth_catalog(&mut snapshot);
    snapshot.functions.push(Function {
        source: "DLL".into(),
        interface: "WIFI_TEST".into(),
        name: "RX_VERIFY_PER".into(),
        convention: Some(2),
        ..Function::default()
    });
    let parameters: Vec<_> = snapshot
        .parameter_links
        .iter()
        .filter(|link| link.function_name == "TX_MULTI_VERIFICATION")
        .cloned()
        .map(|mut link| {
            link.function_name = "RX_VERIFY_PER".into();
            if link.name == "TX_TARGET_POWER" {
                link.name = "RX_TARGET_POWER".into();
            }
            link
        })
        .collect();
    snapshot.parameter_links.extend(parameters);
    for (criteria, names) in [
        (false, vec!["RX_TARGET_POWER"]),
        (true, vec!["PER", "RSSI"]),
    ] {
        for name in names {
            let definition = Definition {
                name: name.into(),
                device_name: "WIFI_TEST".into(),
                kind: "string".into(),
                cardinality: "SINGLE".into(),
                value_pattern: "<value>".into(),
                ..Definition::default()
            };
            if criteria {
                snapshot.criteria_definitions.push(definition);
                snapshot.criteria_links.push(Link {
                    name: name.into(),
                    function_source: "DLL".into(),
                    function_name: "RX_VERIFY_PER".into(),
                    device_name: "WIFI_TEST".into(),
                    required: true,
                    position: None,
                });
            } else {
                snapshot.parameter_definitions.push(definition);
            }
        }
    }
    snapshot.functions.push(Function {
        source: "DLL".into(),
        interface: "WIFI_TEST".into(),
        name: "BRCM_RSSI_CALIBRATION".into(),
        convention: Some(2),
        ..Function::default()
    });
    let calibration: Vec<_> = snapshot
        .parameter_links
        .iter()
        .filter(|link| link.function_name == "RX_VERIFY_PER")
        .cloned()
        .map(|mut link| {
            link.function_name = "BRCM_RSSI_CALIBRATION".into();
            link.required = false;
            link
        })
        .collect();
    snapshot.parameter_links.extend(calibration);
    let ssh = fixture_snapshot();
    snapshot.parameter_definitions.extend(
        ssh.parameter_definitions
            .into_iter()
            .filter(|definition| definition.device_name == "SSH"),
    );
    snapshot.criteria_definitions.extend(
        ssh.criteria_definitions
            .into_iter()
            .filter(|definition| definition.device_name == "SSH"),
    );
    snapshot.parameter_links.extend(
        ssh.parameter_links
            .into_iter()
            .filter(|link| link.device_name == "SSH"),
    );
    snapshot.criteria_links.extend(
        ssh.criteria_links
            .into_iter()
            .filter(|link| link.device_name == "SSH"),
    );
    for function in ["SENDSTR", "CLOSE"] {
        snapshot.functions.push(Function {
            source: "BUILT-IN".into(),
            interface: "SSH".into(),
            name: function.into(),
            convention: Some(1),
            ..Function::default()
        });
        for criteria in [false, true] {
            let link = Link {
                name: if criteria {
                    "EXPECTED_RESPONSE"
                } else {
                    "SESSION_PAYLOAD"
                }
                .into(),
                function_source: "BUILT-IN".into(),
                function_name: function.into(),
                device_name: "SSH".into(),
                required: !criteria,
                position: Some(1),
            };
            if criteria {
                snapshot.criteria_links.push(link);
            } else {
                snapshot.parameter_links.push(link);
            }
        }
    }
    snapshot
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_expands_reviewed_tx_with_independent_text_and_preservation_proof() -> Result<()> {
    let arguments = reviewed_composition_arguments().await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(report["comparison"]["mandatory"]["matched"], 1, "{report}");
    let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
    assert!(
        main.starts_with(concat!(
            "; SYNTHETIC FIXTURE ONLY\r\n; keep order and CRLF\r\n",
            "[TEST FLOW:Normal]\r\n; INSERT TX HERE\r\nTX_DRAFT_0=\"TX_DRAFT_0\"\r\n",
            "; alternate stays inactive\r\n; historical checksum: original-unverified\r\n"
        )),
        "{main}"
    );
    assert!(main.contains(concat!(
        "[TX_DRAFT_0]\r\n",
        "MEASURE=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|BAND=6G&ANT=1,2,4,8&STANDARD=11AG&FREQ=6115&BW=20&DATA_RATE=OFDM6&TX_TARGET_POWER=*V:TX_DRAFT_0-TARGET#&FRAME_COUNT=500|POWER=*V:TX_DRAFT_0-POWER#&EVM=*V:TX_DRAFT_0-EVM#|*V:STATION-Timeout#|NEXT|FAIL|\"\r\n"
    )), "{main}");
    assert_eq!(
        report["draft_files"][5]["text"],
        concat!(
            "; SYNTHETIC FIXTURE ONLY\n; original definitions\n",
            "[TX_DRAFT_0]\nTARGET=15.5dBm\nPOWER=-1~2dB\nEVM=<-35dB\n"
        )
    );
    for index in 1..5 {
        assert_eq!(
            report["draft_files"][index],
            arguments["comparison"]["bundle"]["files"][index]
        );
    }
    assert_eq!(report["diffs"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["limit_links"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        report["comparison"]["validation"]["status"], "valid",
        "{report}"
    );
    assert_eq!(report["artifact_authority"], "synthetic_only");
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(
        report["historical_footers"][0]["verification"],
        "unverified_for_changed_content"
    );
    let mut review = report.clone();
    review["draft_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["source_files"] = serde_json::Value::Null;
    review["comparison"]["validation"]["script_sections"] = serde_json::Value::Null;
    assert!(!review.to_string().contains("synthetic-secret"));
    assert_eq!(compose_report(arguments).await?, report);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_keeps_ambiguous_branch_corrections_blocked_even_with_fixture_approval()
-> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    let source = arguments["template_pack"]["source"]["text"]
        .as_str()
        .unwrap_or("")
        .replace("|NEXT|", "|SET_IPLAS_INFO|");
    arguments["template_pack"]["source"]["text"] = source.into();
    arguments["template_pack"]["corrections"] = serde_json::json!([
        {"before":"|SET_IPLAS_INFO|FAIL|\n","after":"|SET_IPLAS_INFO|FAIL|\"\n","evidence":"Synthetic closing-quote evidence"},
        {"before":"SET_IPLAS_INFO","after":"NEXT","evidence":"Ambiguous target: no operational authority"}
    ]);
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert_eq!(report["diffs"], serde_json::json!([]));
    assert_eq!(report["ready_for_review"], false);
    assert!(report["blockers"].to_string().contains("corrections"));
    assert!(
        report["template_provenance"]["source"]["text"]
            .as_str()
            .is_some_and(|text| text.contains("SET_IPLAS_INFO"))
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_preserves_requirement_order_and_unrelated_repeated_rows() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    let mut second = arguments["comparison"]["plan"]["requirements"][0].clone();
    second["id"] = "TX-SECOND".into();
    second["test"]["frequency"]["value"] = 6435.into();
    arguments["comparison"]["plan"]["requirements"] =
        serde_json::json!([arguments["comparison"]["plan"]["requirements"][0], second]);
    let unrelated = concat!(
        "[UNRELATED]\r\n; inactive alternate remains\r\n",
        "SAME=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=1|NULL|1|QUIT|FAIL|\"\r\n",
        "SAME=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=2|NULL|1|QUIT|FAIL|\"\r\n"
    );
    arguments["comparison"]["bundle"]["files"][0]["text"] = format!(
        "{}{unrelated}",
        arguments["comparison"]["bundle"]["files"][0]["text"]
            .as_str()
            .unwrap_or("")
    )
    .into();
    let report = compose_report(bind_composition_review(arguments).await?).await?;
    let main = report["draft_files"][0]["text"].as_str().unwrap_or("");
    assert!(
        main.contains("TX_DRAFT_0=\"TX_DRAFT_0\"\r\nTX_DRAFT_1=\"TX_DRAFT_1\"\r\n"),
        "{main}"
    );
    assert!(main.contains(unrelated));
    assert_eq!(report["comparison"]["mandatory"]["matched"], 2, "{report}");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_never_substitutes_unbound_template_timing() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    for field in ["source", "corrected"] {
        arguments["template_pack"][field]["text"] = arguments["template_pack"][field]["text"]
            .as_str()
            .unwrap_or("")
            .replace("*V:STATION-Timeout#", "7")
            .into();
    }
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert!(report["blockers"].to_string().contains("timing"));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_binds_approvals_to_all_substantive_inputs_but_not_report_metadata() -> Result<()> {
    let arguments = reviewed_composition_arguments().await?;
    let baseline = compose_report(arguments.clone()).await?;
    let mut metadata = arguments.clone();
    metadata["report_metadata"] =
        serde_json::json!({"request_id":"incidental-123","timestamp":"not-part-of-identity"});
    assert_eq!(compose_report(metadata).await?, baseline);
    for path in [
        "/comparison/plan/requirements/0/test/power_target/value",
        "/comparison/bundle/files/2/text",
        "/template_pack/version",
        "/station_settings/0/key",
    ] {
        let mut changed = arguments.clone();
        let value = changed
            .pointer_mut(path)
            .ok_or_else(|| script_audit_mcp::Error::Knowledge("fixture path missing".into()))?;
        *value = if path.ends_with("value") {
            serde_json::json!(18)
        } else {
            serde_json::json!("changed-without-approval")
        };
        let report = compose_report(changed.clone()).await?;
        assert_eq!(
            report["draft_files"], changed["comparison"]["bundle"]["files"],
            "{path}"
        );
        assert_eq!(report["ready_for_review"], false);
        assert_ne!(report["draft_identity"], baseline["draft_identity"]);
        assert!(
            report["blockers"].to_string().contains("approval")
                || report["blockers"].to_string().contains("reviewed")
        );
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_missing_base_settings_or_real_artifact_authority_never_generates() -> Result<()> {
    let arguments = reviewed_composition_arguments().await?;
    for missing in [
        "base",
        "settings",
        "credential",
        "marker",
        "template_question",
        "flow",
        "collision",
    ] {
        let mut changed = arguments.clone();
        match missing {
            "base" => { changed["comparison"]["bundle"]["files"].as_array_mut().map(|files| files.remove(4)); }
            "settings" => changed["station_settings"] = serde_json::json!([]),
            "credential" => changed["comparison"]["bundle"]["files"][2]["text"] = "; SYNTHETIC FIXTURE ONLY\n[STATION]\nEquipment=synthetic\nRoute=route\nTimeout=1\nSupport=synthetic.dat\n".into(),
            "marker" => changed["comparison"]["bundle"]["files"][3]["text"] = "; real station content cannot use synthetic approval\n".into(),
            "template_question" => changed["template_pack"]["unresolved_questions"] = serde_json::json!(["SET_IPLAS_INFO remains an undefined branch target"]),
            "flow" => changed["flow_anchor"] = "; absent marker\n".into(),
            _ => changed["comparison"]["bundle"]["files"][5]["text"] = "; SYNTHETIC FIXTURE ONLY\n[TX_DRAFT_0]\nKEEP=original\n".into(),
        }
        let changed = bind_composition_review(changed).await?;
        let report = compose_report(changed.clone()).await?;
        assert_eq!(
            report["draft_files"], changed["comparison"]["bundle"]["files"],
            "{missing}"
        );
        assert_eq!(report["diffs"], serde_json::json!([]));
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_preserves_source_conflicts_and_unfinished_radio_coverage() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["plan"] = tx_conflict_arguments()["plan"].clone();
    let report = compose_report(bind_composition_review(arguments.clone()).await?).await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert_eq!(report["comparison"]["coverage"][0]["status"], "conflicting");
    assert!(report["comparison"]["conflicts"][0]["resolved_by"].is_null());
    let mut arguments = reviewed_composition_arguments().await?;
    let tx = arguments["comparison"]["plan"]["requirements"][0].clone();
    let mut rx = tx.clone();
    rx["id"] = "RX-unfinished".into();
    rx["test"]["purpose"] = "rx".into();
    let mut bluetooth = tx.clone();
    bluetooth["id"] = "BT-unfinished".into();
    bluetooth["test"]["technology"] = "bluetooth".into();
    arguments["comparison"]["plan"]["requirements"] = serde_json::json!([tx, rx, bluetooth]);
    let report = compose_report(bind_composition_review(arguments).await?).await?;
    assert_eq!(report["comparison"]["mandatory"]["total"], 3);
    assert_eq!(report["comparison"]["mandatory"]["matched"], 1);
    assert_eq!(report["limit_links"].as_array().map(Vec::len), Some(3));
    assert!(report["blockers"].to_string().contains("RX-unfinished"));
    assert!(report["blockers"].to_string().contains("BT-unfinished"));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_generation_budget_returns_available_files_without_false_ready_truncation()
-> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["bundle"]["files"][3]["text"] =
        format!("; SYNTHETIC FIXTURE ONLY\n{}", "; preserved\n".repeat(4000)).into();
    let original = arguments["comparison"]["plan"]["requirements"][0].clone();
    arguments["comparison"]["plan"]["requirements"] = (0..32)
        .map(|index| {
            let mut requirement = original.clone();
            requirement["id"] = format!("TX-{index}").into();
            requirement["test"]["frequency"]["value"] = (6115 + index * 20).into();
            requirement
        })
        .collect::<Vec<_>>()
        .into();
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(report["draft_files"].as_array().map(Vec::len), Some(6));
    assert_eq!(
        report["draft_files"][3],
        arguments["comparison"]["bundle"]["files"][3]
    );
    assert_eq!(report["comparison"]["mandatory"]["total"], 32);
    assert!(
        report["comparison"]["mandatory"]["matched"]
            .as_u64()
            .is_some_and(|count| count > 0 && count < 32)
    );
    assert!(report["blockers"].to_string().contains("budget"));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_reuses_scoped_catalog_without_defaults_and_hashes_knowledge_deterministically()
-> Result<()> {
    let arguments = reviewed_composition_arguments().await?;
    let baseline = compose_report(arguments.clone()).await?;
    let mut reordered = tx_plan_snapshot();
    reordered.functions.reverse();
    reordered.parameter_links.reverse();
    reordered.parameter_definitions.reverse();
    reordered.criteria_links.reverse();
    reordered.criteria_definitions.reverse();
    assert_eq!(
        compose_report_with_snapshot(arguments.clone(), reordered).await?,
        baseline
    );
    let mut changed = tx_plan_snapshot();
    for definition in &mut changed.parameter_definitions {
        if definition.name == "TX_TARGET_POWER" {
            definition.default_value = Some("99dBm".into());
        }
    }
    let report = compose_report_with_snapshot(arguments.clone(), changed).await?;
    assert_ne!(
        report["input_identities"]["catalog"],
        baseline["input_identities"]["catalog"]
    );
    assert_ne!(report["draft_identity"], baseline["draft_identity"]);
    assert_eq!(report["draft_files"], baseline["draft_files"]);
    let mut unrelated = tx_plan_snapshot();
    for definition in &mut unrelated.parameter_definitions {
        definition.device_name = "UNRELATED".into();
    }
    let report = compose_report_with_snapshot(arguments.clone(), unrelated).await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert!(report["blockers"].to_string().contains("catalog"));
    let mut incomplete = arguments.clone();
    incomplete["comparison"]["plan"]["requirements"][0]["test"]["power_target"] =
        serde_json::Value::Null;
    let incomplete = bind_composition_review(incomplete).await?;
    let report = compose_report(incomplete.clone()).await?;
    assert_eq!(
        report["draft_files"],
        incomplete["comparison"]["bundle"]["files"]
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_redacts_declared_credential_roles_without_password_name_heuristics() -> Result<()>
{
    for binding in [
        "AuthBlob=custom-credential-08\n",
        "AuthBlob=*V:AUTH-Value#\nValue=custom-credential-08\n",
    ] {
        let mut arguments = reviewed_composition_arguments().await?;
        arguments["comparison"]["bundle"]["files"][5]["text"] =
            format!("; SYNTHETIC FIXTURE ONLY\n[AUTH]\n{binding}").into();
        arguments["station_settings"][4] = serde_json::json!({
            "role":"credential","file":"TEST_SPEC.ini","section":"AUTH","key":"AuthBlob"
        });
        let report = compose_report(bind_composition_review(arguments).await?).await?;
        assert_eq!(report["comparison"]["mandatory"]["matched"], 1);
        assert!(
            report["draft_files"][5]["text"]
                .as_str()
                .is_some_and(|text| text.contains(binding))
        );
        assert!(!report["diffs"].to_string().contains("custom-credential-08"));
        assert!(report["diffs"].to_string().contains("[REDACTED]"));
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_redaction_preserves_hashes_schema_keys_and_invalid_precedence() -> Result<()> {
    for credential in ["256", "invalid", "status"] {
        let mut arguments = reviewed_composition_arguments().await?;
        arguments["comparison"]["bundle"]["files"][2]["text"] =
            arguments["comparison"]["bundle"]["files"][2]["text"]
                .as_str()
                .unwrap_or("")
                .replace("synthetic-secret", credential)
                .into();
        if credential != "256" {
            arguments["comparison"]["bundle"]["files"][0]["text"] = format!("{}[BROKEN]\nBAD=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=1|NULL|1|SET_IPLAS_INFO|FAIL|\"\n",
                arguments["comparison"]["bundle"]["files"][0]["text"].as_str().unwrap_or("")).into();
        }
        let preview = compose_report(arguments.clone()).await?;
        assert!(
            preview["input_identities"]["base"]
                .as_str()
                .is_some_and(|identity| identity.starts_with("sha256:")),
            "{credential}"
        );
        let report = compose_report(bind_composition_review(arguments).await?).await?;
        assert_eq!(
            report["comparison"]["mandatory"]["matched"], 1,
            "{credential}"
        );
        if credential != "256" {
            assert_eq!(report["status"], "invalid", "{credential}");
            assert_eq!(report["comparison"]["status"], "invalid", "{credential}");
            assert_eq!(
                report["comparison"]["validation"]["status"], "invalid",
                "{credential}"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_secret_redaction_never_rewrites_inserted_markers() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["bundle"]["sensitive_values"] = serde_json::json!(["s", "D"]);
    arguments["template_pack"]["corrections"][0]["evidence"] = "s".into();
    let report = compose_report(arguments).await?;
    assert_eq!(
        report["template_provenance"]["corrections"][0]["evidence"],
        "[REDACTED]"
    );
    assert!(report.to_string().len() < 100_000);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_combined_plan_budget_preserves_available_partial_drafts() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    let original = arguments["comparison"]["plan"]["requirements"][0].clone();
    arguments["comparison"]["plan"]["requirements"] = (0..128)
        .map(|index| {
            let mut requirement = original.clone();
            requirement["id"] = format!("TX-BUDGET-{index}").into();
            requirement["test"]["frequency"]["value"] = (6115 + index * 20).into();
            requirement
        })
        .collect::<Vec<_>>()
        .into();
    let typed: script_audit_mcp::bundle::compose::ComposeBundleRequest =
        serde_json::from_value(arguments.clone())
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let initial = serde_json::to_vec(&typed)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?
        .len();
    let padding = 1_025_000_usize.saturating_sub(initial);
    let mut comments = String::from("; SYNTHETIC FIXTURE ONLY\n");
    for chunk in vec![b'x'; padding].chunks(8000) {
        comments.push(';');
        comments.push_str(&"x".repeat(chunk.len()));
        comments.push('\n');
    }
    arguments["comparison"]["bundle"]["files"][3]["text"] = comments.into();
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(report["draft_files"].as_array().map(Vec::len), Some(6));
    assert_eq!(
        report["draft_files"][3],
        arguments["comparison"]["bundle"]["files"][3]
    );
    assert!(
        report["limit_links"]
            .as_array()
            .is_some_and(|links| !links.is_empty() && links.len() < 384)
    );
    assert!(report["blockers"].to_string().contains("budget"));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_review_redaction_preserves_typed_reports_and_marker_credentials() -> Result<()> {
    for credential in [
        "[REDACTED]suffix",
        "256",
        "invalid",
        "resolved",
        "reachable",
        "supported",
    ] {
        let mut arguments = reviewed_composition_arguments().await?;
        arguments["comparison"]["bundle"]["files"][2]["text"] =
            arguments["comparison"]["bundle"]["files"][2]["text"]
                .as_str()
                .unwrap_or("")
                .replace("synthetic-secret", credential)
                .into();
        arguments["comparison"]["bundle"]["files"][0]["text"] = format!("{}; Password={credential}\r\n[BROKEN]\nBAD=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=1|NULL|1|SET_IPLAS_INFO|FAIL|\"\n", arguments["comparison"]["bundle"]["files"][0]["text"].as_str().unwrap_or("")).into();
        let report = compose_report(bind_composition_review(arguments).await?).await?;
        assert!(
            !report["diffs"]
                .to_string()
                .contains(&format!("Password={credential}")),
            "{credential}"
        );
        assert_eq!(
            report["template_provenance"]["approval"]["subject_identity"],
            report["input_identities"]["template_pack"],
            "{credential}"
        );
        assert_eq!(
            report["comparison"]["validation"]["layers"]["control_flow"], "invalid",
            "{credential}"
        );
        assert!(
            report["comparison"]["validation"]["execution"]
                .as_array()
                .is_some_and(|execution| execution.iter().any(|row| row["references"]
                    == "resolved"
                    && row["reachability"] == "reachable")),
            "{credential}"
        );
        assert!(
            report["comparison"]["validation"]["execution_edges"]
                .as_array()
                .is_some_and(|edges| edges.iter().any(|edge| edge["certainty"] == "supported")),
            "{credential}"
        );
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_review_expanded_row_budget_preserves_available_base() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    let mut main = String::from("; SYNTHETIC FIXTURE ONLY\n[TEST FLOW:Normal]\n; INSERT TX HERE\n");
    main.push_str(&"HOLD=\"HOLD\"\n".repeat(128));
    main.push_str("[HOLD]\n");
    for index in 0..128 {
        main.push_str(&format!(
            "KEEP{index}=\"VOID|VOID|NULL|NULL|1|NEXT|FAIL|\"\n"
        ));
    }
    arguments["comparison"]["bundle"]["files"][0]["text"] = main.into();
    arguments["flow_anchor"] = "; INSERT TX HERE\n".into();
    let arguments = bind_composition_review(arguments).await?;
    let report = compose_report(arguments.clone()).await?;
    assert_eq!(
        report["draft_files"],
        arguments["comparison"]["bundle"]["files"]
    );
    assert_eq!(report["diffs"], serde_json::json!([]));
    assert!(report["blockers"].to_string().contains("budget"));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn compose_large_redaction_input_stays_bounded_without_cascading() -> Result<()> {
    let mut arguments = reviewed_composition_arguments().await?;
    arguments["comparison"]["bundle"]["sensitive_values"] =
        serde_json::json!(["s", "D", "E", "R", "A", "C", "T", "[", "]"]);
    arguments["template_pack"]["corrections"][0]["evidence"] = "s".repeat(800_000).into();
    let report = compose_report(arguments).await?;
    let evidence = report["template_provenance"]["corrections"][0]["evidence"]
        .as_str()
        .unwrap_or("");
    assert_eq!(evidence.len(), 8_000_000);
    assert!(evidence.starts_with("[REDACTED][REDACTED]"));
    assert!(report.to_string().len() < 16_777_216);
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
fn tx_plan_snapshot() -> Snapshot {
    let mut snapshot = fixture_snapshot();
    snapshot.parameter_definitions.clear();
    snapshot.parameter_links.clear();
    snapshot.criteria_definitions.clear();
    snapshot.criteria_links.clear();
    for (criteria, names) in [
        (
            false,
            vec![
                "BAND",
                "ANT",
                "STANDARD",
                "FREQ",
                "BW",
                "DATA_RATE",
                "TX_TARGET_POWER",
                "FRAME_COUNT",
            ],
        ),
        (true, vec!["POWER", "EVM"]),
    ] {
        for name in names {
            let definition = Definition {
                name: name.into(),
                device_name: "WIFI_TEST".into(),
                kind: "string".into(),
                cardinality: "SINGLE".into(),
                value_pattern: "<value>".into(),
                ..Definition::default()
            };
            let link = Link {
                name: name.into(),
                function_source: "DLL".into(),
                function_name: "TX_MULTI_VERIFICATION".into(),
                device_name: "WIFI_TEST".into(),
                position: None,
                required: true,
            };
            if criteria {
                snapshot.criteria_definitions.push(definition);
                snapshot.criteria_links.push(link);
            } else {
                snapshot.parameter_definitions.push(definition);
                snapshot.parameter_links.push(link);
            }
        }
    }
    snapshot
}

#[cfg(feature = "mcp")]
async fn call_plan(arguments: serde_json::Value) -> Result<rmcp::model::CallToolResult> {
    struct TxCatalog;
    impl script_audit_mcp::Catalog for TxCatalog {
        fn snapshot(&self) -> Result<Snapshot> {
            let mut snapshot = tx_plan_snapshot();
            snapshot.functions.push(Function {
                source: "DLL".into(),
                interface: "WIFI_TEST".into(),
                name: "RX_VERIFY_PER".into(),
                convention: Some(2),
                ..Function::default()
            });
            for (criteria, names) in [
                (
                    false,
                    vec![
                        "BAND",
                        "ANT",
                        "STANDARD",
                        "FREQ",
                        "BW",
                        "DATA_RATE",
                        "RX_TARGET_POWER",
                        "FRAME_COUNT",
                    ],
                ),
                (true, vec!["PER", "RSSI"]),
            ] {
                for name in names {
                    let definition = Definition {
                        name: name.into(),
                        device_name: "WIFI_TEST".into(),
                        kind: "string".into(),
                        cardinality: "SINGLE".into(),
                        value_pattern: "<value>".into(),
                        ..Definition::default()
                    };
                    let link = Link {
                        name: name.into(),
                        function_source: "DLL".into(),
                        function_name: "RX_VERIFY_PER".into(),
                        device_name: "WIFI_TEST".into(),
                        required: name != "RSSI",
                        position: None,
                    };
                    if criteria {
                        if !snapshot
                            .criteria_definitions
                            .iter()
                            .any(|existing| existing.name == name)
                        {
                            snapshot.criteria_definitions.push(definition);
                        }
                        snapshot.criteria_links.push(link);
                    } else {
                        if !snapshot
                            .parameter_definitions
                            .iter()
                            .any(|existing| existing.name == name)
                        {
                            snapshot.parameter_definitions.push(definition);
                        }
                        snapshot.parameter_links.push(link);
                    }
                }
            }
            snapshot.functions.push(Function {
                source: "DLL".into(),
                interface: "WIFI_TEST".into(),
                name: "BRCM_RSSI_CALIBRATION".into(),
                convention: Some(2),
                ..Function::default()
            });
            for links in [&mut snapshot.parameter_links, &mut snapshot.criteria_links] {
                let calibration: Vec<_> = links
                    .iter()
                    .filter(|link| link.function_name == "RX_VERIFY_PER")
                    .cloned()
                    .map(|mut link| {
                        link.function_name = "BRCM_RSSI_CALIBRATION".into();
                        link.required = false;
                        link
                    })
                    .collect();
                links.extend(calibration);
            }
            add_bluetooth_catalog(&mut snapshot);
            snapshot.parameter_definitions.push(Definition {
                name: "SESSION_PAYLOAD".into(),
                device_name: "SSH".into(),
                kind: "string".into(),
                cardinality: "SINGLE".into(),
                value_pattern: "<session>@<payload>".into(),
                ..Definition::default()
            });
            snapshot.parameter_links.push(Link {
                name: "SESSION_PAYLOAD".into(),
                function_source: "BUILT-IN".into(),
                function_name: "OPEN".into(),
                device_name: "SSH".into(),
                required: true,
                position: None,
            });
            Ok(snapshot)
        }
    }
    let request = serde_json::from_value(arguments)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(TxCatalog))
        .compare_plan_to_bundle(rmcp::handler::server::wrapper::Parameters(request))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))
}

#[cfg(feature = "mcp")]
fn add_bluetooth_catalog(snapshot: &mut Snapshot) {
    for (function, parameters, criteria) in [
        (
            "TX_MULTI_VERIFY",
            vec!["ANT", "FREQ", "TX_TARGET_POWER"],
            vec!["POWER", "FREQ_ERROR_KHZ"],
        ),
        (
            "RX_VERIFY_PER",
            vec!["ANT", "FREQ", "RX_TARGET_POWER", "FRAME_COUNT"],
            vec!["PER"],
        ),
        ("DUT_INSERT", vec!["TECH", "DUT_NAME", "DUT_CASE"], vec![]),
    ] {
        snapshot.functions.push(Function {
            source: "DLL".into(),
            interface: "IOT".into(),
            name: function.into(),
            convention: Some(2),
            ..Function::default()
        });
        for (criteria, names) in [(false, parameters), (true, criteria)] {
            let (definitions, links) = if criteria {
                (
                    &mut snapshot.criteria_definitions,
                    &mut snapshot.criteria_links,
                )
            } else {
                (
                    &mut snapshot.parameter_definitions,
                    &mut snapshot.parameter_links,
                )
            };
            for name in names {
                if !definitions
                    .iter()
                    .any(|existing| existing.name == name && existing.device_name == "IOT")
                {
                    definitions.push(Definition {
                        name: name.into(),
                        device_name: "IOT".into(),
                        kind: "string".into(),
                        cardinality: "SINGLE".into(),
                        value_pattern: "<value>".into(),
                        ..Definition::default()
                    });
                }
                links.push(Link {
                    name: name.into(),
                    function_source: "DLL".into(),
                    function_name: function.into(),
                    device_name: "IOT".into(),
                    required: true,
                    position: None,
                });
            }
        }
    }
}

#[cfg(feature = "mcp")]
fn bluetooth_plan_arguments() -> serde_json::Value {
    serde_json::json!({
        "bundle": bundle_arguments(concat!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
            "BT_SETUP=\"DLLIOT|DUT_INSERT|TECH=BT&DUT_NAME=fixture&DUT_CASE=fixture|NULL|20000|NEXT|FAIL\"\n",
            "BT_TX_LOW=\"DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2404&TX_TARGET_POWER=20|POWER=-3~1&FREQ_ERROR_KHZ=-150~150|100000|NEXT|FAIL\"\n",
            "BT_TX_HIGH=\"DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2480&TX_TARGET_POWER=20|POWER=-3~1&FREQ_ERROR_KHZ=-150~150|100000|QUIT|FAIL\"\n"
        )),
        "flow_variant":"normal",
        "plan":{
            "controlling_source":"plan", "station":"HH5K Wireless Test_2",
            "sources":[{"id":"plan","revision":"3.8","kind":"test_plan","approved":true}],
            "requirements":[{
                "id":"BT-TX-2404", "applicability":"mandatory", "depends_on":["BT-SETUP"],
                "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2404 MHz; TX 20 dBm, -3/+1 dB; frequency offset +/-150 kHz"}],
                "test":{
                    "technology":"bluetooth", "purpose":"tx",
                    "frequency":{"value":2404,"unit":"MHz"},
                    "chains":{"kind":"bitmask","value":1},
                    "power_target":{"value":20,"unit":"dBm"},
                    "power_tolerance":{"lower":-3,"upper":1,"unit":"dB"},
                    "frequency_offset":{"lower":-150,"upper":150,"unit":"kHz"}
                }
            },{
                "id":"BT-TX-2480", "applicability":"mandatory", "depends_on":["BT-SETUP"],
                "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2480 MHz; TX 20 dBm, -3/+1 dB; frequency offset +/-150 kHz"}],
                "test":{
                    "technology":"bluetooth", "purpose":"tx",
                    "frequency":{"value":2480,"unit":"MHz"},
                    "chains":{"kind":"bitmask","value":1},
                    "power_target":{"value":20,"unit":"dBm"},
                    "power_tolerance":{"lower":-3,"upper":1,"unit":"dB"},
                    "frequency_offset":{"lower":-150,"upper":150,"unit":"kHz"}
                }
            },{
                "id":"BT-SETUP", "applicability":"mandatory",
                "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup","excerpt":"Bluetooth setup before measurement; synthetic station payload"}],
                "test":{
                    "technology":"bluetooth", "purpose":"setup",
                    "procedure":{"device":"DLLIOT","function":"DUT_INSERT","parameters":"TECH=BT&DUT_NAME=fixture&DUT_CASE=fixture","criteria":"NULL"}
                }
            }]
        }
    })
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_tx_matches_independent_frequency_power_and_offset_requirements()
-> Result<()> {
    let arguments = bluetooth_plan_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["mandatory"],
        serde_json::json!({"total":3,"matched":3})
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "BT_TX_LOW");
    assert_eq!(report["coverage"][1]["evidence"][0]["row"], "BT_TX_HIGH");
    assert_eq!(
        report["coverage"][0]["provenance"],
        arguments["plan"]["requirements"][0]["provenance"]
    );
    assert_eq!(report["validation"]["hardware_verification"], "unchecked");
    Ok(())
}

#[cfg(feature = "mcp")]
fn bluetooth_rx_arguments() -> serde_json::Value {
    use serde_json::json;
    let mut arguments = bluetooth_plan_arguments();
    replace_plan_script(&mut arguments, "100000|QUIT|FAIL", "100000|NEXT|FAIL");
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default();
    arguments["bundle"]["files"][0]["text"] = json!(format!(
        "{text}{}",
        concat!(
            "BT_RX_LOW=\"DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2404&RX_TARGET_POWER=-87&FRAME_COUNT=500|PER=<30.8%|100000|NEXT|FAIL\"\n",
            "BT_RX_HIGH=\"DLLIOT|RX_VERIFY_PER|ANT=1&FREQ=2480&RX_TARGET_POWER=-87&FRAME_COUNT=500|PER=<30.8%|100000|QUIT|FAIL\"\n"
        )
    ));
    for requirement in [
        json!({
            "id":"BT-RX-2404", "applicability":"mandatory", "depends_on":["BT-SETUP"],
            "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2404 MHz; RX -87 dBm, 500 packets; PER strictly below 30.8%"}],
            "test":{
                "technology":"bluetooth", "purpose":"rx", "frequency":{"value":2404,"unit":"MHz"},
                "chains":{"kind":"bitmask","value":1}, "input_level":{"value":-87,"unit":"dBm"},
                "packet_count":500, "per":{"operator":"lt","threshold":{"value":30.8,"unit":"%"}}
            }
        }),
        json!({
            "id":"BT-RX-2480", "applicability":"mandatory", "depends_on":["BT-SETUP"],
            "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2480 MHz; RX -87 dBm, 500 packets; PER strictly below 30.8%"}],
            "test":{
                "technology":"bluetooth", "purpose":"rx", "frequency":{"value":2480,"unit":"MHz"},
                "chains":{"kind":"bitmask","value":1}, "input_level":{"value":-87,"unit":"dBm"},
                "packet_count":500, "per":{"operator":"lt","threshold":{"value":30.8,"unit":"%"}}
            }
        }),
    ] {
        if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
            requirements.push(requirement);
        }
    }
    arguments
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_rx_is_independent_and_missing_rx_is_not_replaced_by_tx_or_wifi()
-> Result<()> {
    let arguments = bluetooth_rx_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["mandatory"],
        serde_json::json!({"total":5,"matched":5})
    );
    assert_eq!(report["coverage"][3]["evidence"][0]["row"], "BT_RX_LOW");
    assert_eq!(report["coverage"][4]["evidence"][0]["row"], "BT_RX_HIGH");
    let mut missing = arguments;
    replace_plan_script(&mut missing, "BT_RX_LOW=", ";BT_RX_LOW=");
    replace_plan_script(&mut missing, "BT_RX_HIGH=", ";BT_RX_HIGH=");
    let report = plan_report(missing).await?;
    assert_eq!(report["coverage"][3]["status"], "missing", "{report}");
    assert_eq!(report["coverage"][4]["status"], "missing", "{report}");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_tx_preserves_power_offset_frequency_and_unit_boundaries() -> Result<()> {
    for (from, to, expected) in [
        ("TX_TARGET_POWER=20", "TX_TARGET_POWER=19.9", "conflicting"),
        ("TX_TARGET_POWER=20", "TX_TARGET_POWER=20.1", "conflicting"),
        ("TX_TARGET_POWER=20", "TX_TARGET_POWER=20dBm", "matched"),
        ("TX_TARGET_POWER=20", "TX_TARGET_POWER=20dB", "unknown"),
        ("POWER=-3~1", "POWER=-2.9~1", "conflicting"),
        ("POWER=-3~1", "POWER=-3.1~1", "conflicting"),
        ("POWER=-3~1", "POWER=-3~0.9", "conflicting"),
        ("POWER=-3~1", "POWER=-3~1.1", "conflicting"),
        ("POWER=-3~1", "POWER=-3~1dB", "matched"),
        ("POWER=-3~1", "POWER=-3~1dBm", "unknown"),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-149.9~150",
            "conflicting",
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-150.1~150",
            "conflicting",
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-150~149.9",
            "conflicting",
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-150~150.1",
            "conflicting",
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-150~150kHz",
            "matched",
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=-150~150MHz",
            "unknown",
        ),
        ("FREQ=2404", "FREQ=2402", "conflicting"),
        ("FREQ=2404", "FREQ=2404MHz", "matched"),
        ("FREQ=2404", "FREQ=2404kHz", "unknown"),
        ("ANT=1", "ANT=2", "conflicting"),
    ] {
        let mut arguments = bluetooth_plan_arguments();
        replace_plan_script(&mut arguments, "BT_TX_HIGH=", ";BT_TX_HIGH=");
        if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
            requirements.remove(1);
        }
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], expected,
            "{from} -> {to}: {report}"
        );
        assert_eq!(
            report["ready_for_review"],
            expected == "matched",
            "{report}"
        );
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_rx_preserves_strict_per_exact_counts_and_input_units() -> Result<()> {
    for (from, to, expected) in [
        ("FRAME_COUNT=500", "FRAME_COUNT=499", "conflicting"),
        ("FRAME_COUNT=500", "FRAME_COUNT=501", "conflicting"),
        (
            "RX_TARGET_POWER=-87",
            "RX_TARGET_POWER=-87.1",
            "conflicting",
        ),
        (
            "RX_TARGET_POWER=-87",
            "RX_TARGET_POWER=-86.9",
            "conflicting",
        ),
        ("RX_TARGET_POWER=-87", "RX_TARGET_POWER=-87dBm", "matched"),
        ("RX_TARGET_POWER=-87", "RX_TARGET_POWER=-87dB", "unknown"),
        ("PER=<30.8%", "PER=<30.7%", "conflicting"),
        ("PER=<30.8%", "PER=<30.9%", "conflicting"),
        ("PER=<30.8%", "PER=>30.8%", "conflicting"),
        ("PER=<30.8%", "PER=30.8%", "unknown"),
        ("PER=<30.8%", "PER=<=30.8%", "unknown"),
        ("PER=<30.8%", "PER=<30.8dB", "unknown"),
        ("PER=<30.8%", "PER=<0.308", "unknown"),
        (
            "DLLIOT|RX_VERIFY_PER",
            "DLLIOT#UNPROVEN|RX_VERIFY_PER",
            "unknown",
        ),
    ] {
        let mut arguments = bluetooth_rx_arguments();
        replace_plan_script(&mut arguments, "BT_RX_HIGH=", ";BT_RX_HIGH=");
        if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
            requirements.remove(4);
        }
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][3]["status"], expected,
            "{from} -> {to}: {report}"
        );
        assert_eq!(
            report["ready_for_review"],
            expected == "matched",
            "{report}"
        );
    }
    for operator in ["le", "eq"] {
        let mut arguments = bluetooth_rx_arguments();
        arguments["plan"]["requirements"][3]["test"]["per"]["operator"] =
            serde_json::json!(operator);
        let report = plan_report(arguments).await?;
        assert_eq!(report["coverage"][3]["status"], "conflicting", "{report}");
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_requires_sourced_successful_setup_and_never_borrows_wifi() -> Result<()> {
    for (from, to, setup, measurement) in [
        ("BT_SETUP=", ";BT_SETUP=", "missing", "conflicting"),
        ("TECH=BT", "TECH=ZIGBEE", "conflicting", "conflicting"),
        (
            "20000|NEXT|FAIL",
            "20000|NEXT|BT_TX_LOW",
            "matched",
            "conflicting",
        ),
        ("TECH=BT", "TECH=*E:Radio-Mode#", "unknown", "unknown"),
    ] {
        let mut arguments = bluetooth_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][2]["status"], setup,
            "{from} -> {to}: {report}"
        );
        assert_eq!(
            report["coverage"][0]["status"], measurement,
            "{from} -> {to}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    let mut arguments = bluetooth_plan_arguments();
    arguments["plan"]["requirements"][0]["depends_on"] = serde_json::json!([]);
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "unknown", "{report}");
    let mut arguments = bluetooth_rx_arguments();
    arguments["bundle"] = tx_plan_arguments()["bundle"].clone();
    let report = plan_report(arguments).await?;
    for index in [0, 1, 3, 4] {
        assert_eq!(report["coverage"][index]["status"], "missing", "{report}");
    }
    assert_eq!(report["mandatory"]["matched"], 0);
    assert_eq!(report["additional"][0]["row"], "OFDM6");
    Ok(())
}

#[cfg(feature = "mcp")]
fn bluetooth_conflict_arguments() -> serde_json::Value {
    use serde_json::json;
    let mut arguments = bluetooth_plan_arguments();
    let low = arguments["plan"]["requirements"][0]["test"].clone();
    let high = arguments["plan"]["requirements"][1]["test"].clone();
    let mut channel_zero = low.clone();
    channel_zero["frequency"] = json!(null);
    channel_zero["channel"] = json!(0);
    let mut channel_seventy_eight = high.clone();
    channel_seventy_eight["frequency"] = json!(null);
    channel_seventy_eight["channel"] = json!(78);
    arguments["plan"]["conflicts"] = json!([
        {"id":"BT-low-channel-frequency", "requirement_id":"BT-TX-2404", "kind":"within_source", "statements":[
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth success matrix","excerpt":"CH0"},"test":channel_zero},
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2404 MHz"},"test":low}
        ]},
        {"id":"BT-high-channel-frequency", "requirement_id":"BT-TX-2480", "kind":"within_source", "statements":[
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth success matrix","excerpt":"CH78"},"test":channel_seventy_eight},
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"2480 MHz"},"test":high}
        ]},
        {"id":"BT-incorrect-cross-reference", "requirement_id":"BT-TX-2404", "kind":"within_source", "statements":[
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth success matrix cross-reference","excerpt":"The success-matrix reference points to another section/table; intended target unresolved."},"test":low},
            {"provenance":{"source_id":"plan","revision":"3.8","location":"section 6.5, Bluetooth setup/result table","excerpt":"Bluetooth result and setup statements; cross-reference not approved."},"test":low}
        ]}
    ]);
    arguments
}

#[cfg(feature = "mcp")]
fn bluetooth_exception(
    arguments: &serde_json::Value,
    conflict: usize,
    requirement: usize,
) -> serde_json::Value {
    serde_json::json!({
        "id":format!("synthetic-BT-approval-{conflict}"),
        "conflict_id":arguments["plan"]["conflicts"][conflict]["id"],
        "requirement_id":arguments["plan"]["requirements"][requirement]["id"],
        "station":"HH5K Wireless Test_2", "source_revisions":{"plan":"3.8"},
        "decision":arguments["plan"]["requirements"][requirement]["test"],
        "rationale":"Synthetic reviewer chooses only the identified statement/reference conflict.",
        "approver":"fixture-reviewer", "approval_evidence":"fixture approval; not real station authorization"
    })
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_preserves_channels_frequencies_and_bad_cross_references_without_precedence()
-> Result<()> {
    let arguments = bluetooth_conflict_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["status"], "invalid", "{report}");
    assert_eq!(report["coverage"][0]["status"], "conflicting");
    assert_eq!(report["coverage"][1]["status"], "conflicting");
    for index in 0..3 {
        assert_eq!(
            report["conflicts"][index]["resolved_by"],
            serde_json::Value::Null
        );
        for field in ["id", "kind", "requirement_id"] {
            assert_eq!(
                report["conflicts"][index]["conflict"][field],
                arguments["plan"]["conflicts"][index][field]
            );
        }
        for statement in 0..2 {
            assert_eq!(
                report["conflicts"][index]["conflict"]["statements"][statement]["provenance"],
                arguments["plan"]["conflicts"][index]["statements"][statement]["provenance"]
            );
        }
    }
    assert_eq!(
        report["conflicts"][0]["conflict"]["statements"][0]["test"]["channel"],
        0
    );
    assert_eq!(
        report["conflicts"][1]["conflict"]["statements"][0]["test"]["channel"],
        78
    );
    assert_eq!(
        report["conflicts"][0]["conflict"]["statements"][1]["test"]["frequency"]["value"].as_f64(),
        Some(2404.0)
    );
    assert_eq!(
        report["conflicts"][1]["conflict"]["statements"][1]["test"]["frequency"]["value"].as_f64(),
        Some(2480.0)
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_exceptions_clear_only_current_identified_conflicts_with_evidence()
-> Result<()> {
    use serde_json::json;
    let original = bluetooth_conflict_arguments();
    for (key, value) in [
        ("approval_evidence", json!("")),
        ("rationale", json!("")),
        ("approver", json!("")),
        ("source_revisions", json!({"plan":"3.7"})),
        ("conflict_id", json!("unrelated-conflict")),
        ("requirement_id", json!("BT-TX-2480")),
        ("station", json!("other station")),
    ] {
        let mut arguments = original.clone();
        let mut exception = bluetooth_exception(&arguments, 0, 0);
        exception[key] = value;
        arguments["plan"]["exceptions"] = json!([exception]);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["conflicts"][0]["resolved_by"],
            serde_json::Value::Null,
            "{key}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
        assert!(
            report["blockers"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item
                    .as_str()
                    .is_some_and(|text| text.contains("exception is unrelated")))),
            "{report}"
        );
    }
    let mut arguments = original;
    let low = bluetooth_exception(&arguments, 0, 0);
    arguments["plan"]["exceptions"] = json!([low]);
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(
        report["conflicts"][0]["resolved_by"],
        "synthetic-BT-approval-0"
    );
    assert_eq!(
        report["conflicts"][1]["resolved_by"],
        serde_json::Value::Null
    );
    assert_eq!(
        report["conflicts"][2]["resolved_by"],
        serde_json::Value::Null
    );
    assert_eq!(report["coverage"][0]["status"], "conflicting");
    assert_eq!(report["ready_for_review"], false);
    let high = bluetooth_exception(&arguments, 1, 1);
    let reference = bluetooth_exception(&arguments, 2, 0);
    arguments["plan"]["exceptions"] = json!([low, high, reference]);
    let report = plan_report(arguments).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["conflicts"][2]["resolved_by"],
        "synthetic-BT-approval-2"
    );
    assert_eq!(report["validation"]["hardware_verification"], "unchecked");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_channel_decisions_are_explicit_not_automatic_conversion() -> Result<()> {
    use serde_json::json;
    let mut arguments = bluetooth_conflict_arguments();
    let frequency_decision = bluetooth_exception(&arguments, 0, 0);
    arguments["plan"]["requirements"][0]["test"] =
        arguments["plan"]["conflicts"][0]["statements"][0]["test"].clone();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting");
    if let Some(conflicts) = arguments["plan"]["conflicts"].as_array_mut() {
        conflicts.truncate(1);
    }
    arguments["plan"]["exceptions"] = json!([frequency_decision]);
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(
        report["coverage"][0]["test"]["frequency"]["value"].as_f64(),
        Some(2404.0)
    );
    assert_eq!(
        report["coverage"][0]["test"]["channel"],
        serde_json::Value::Null
    );
    arguments["plan"]["exceptions"][0]["decision"]["frequency"]["value"] = json!(2402);
    let report = plan_report(arguments).await?;
    assert_eq!(
        report["conflicts"][0]["resolved_by"],
        serde_json::Value::Null
    );
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_does_not_reuse_a_setup_after_radio_reselection() -> Result<()> {
    use serde_json::json;
    for identity in [
        "DLLIOT|DUT_INSERT",
        "DLLIOT|dut_insert",
        "DLLiot|DUT_INSERT",
    ] {
        for via_macro in [false, true] {
            let mut arguments = bluetooth_plan_arguments();
            if via_macro {
                replace_plan_script(
                    &mut arguments,
                    "BT_TX_LOW=",
                    concat!(
                        "OTHER_RADIO=\"MACRO|SELECT_OTHER|TECH=ZIGBEE|NULL|20000|NEXT|FAIL\"\n",
                        "BT_TX_LOW="
                    ),
                );
                if let Some(files) = arguments["bundle"]["files"].as_array_mut() {
                    files.push(json!({"name":"MACRO_LIST.ini","text":format!(
                        "[SELECT_OTHER]\nCHANGE=\"{identity}|TECH=*V:Macro-Param_TECH#&DUT_NAME=fixture&DUT_CASE=fixture|NULL|20000|QUIT|FAIL\"\n"
                    )}));
                }
            } else {
                replace_plan_script(
                    &mut arguments,
                    "BT_TX_LOW=",
                    &format!(
                        "OTHER_RADIO=\"{identity}|TECH=ZIGBEE&DUT_NAME=fixture&DUT_CASE=fixture|NULL|20000|NEXT|FAIL\"\nBT_TX_LOW="
                    ),
                );
            }
            let report = plan_report(arguments).await?;
            assert_eq!(
                report["coverage"][0]["status"], "unknown",
                "{identity}, macro={via_macro}: {report}"
            );
            assert_eq!(report["coverage"][1]["status"], "unknown", "{report}");
            assert_eq!(report["ready_for_review"], false);
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_resolves_supplied_specs_but_keeps_runtime_bindings_unchecked() -> Result<()>
{
    use serde_json::json;
    let mut arguments = bluetooth_plan_arguments();
    replace_plan_script(
        &mut arguments,
        "POWER=-3~1&FREQ_ERROR_KHZ=-150~150",
        "*V:BT_TX_SPEC#",
    );
    if let Some(files) = arguments["bundle"]["files"].as_array_mut() {
        files.push(json!({"name":"TEST_SPEC.ini","text":"[BT_TX_SPEC]\nPOWER=-3~1\nFREQ_ERROR_KHZ=-150~150\n"}));
    }
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["validation"]["source_files"],
        arguments["bundle"]["files"]
    );
    for (from, to, reference, value, rx) in [
        (
            "FREQ=2404",
            "FREQ=*E:BT-Frequency#",
            "*E:BT-Frequency#",
            "2404",
            false,
        ),
        (
            "TX_TARGET_POWER=20",
            "TX_TARGET_POWER=*E:BT-Power#",
            "*E:BT-Power#",
            "20",
            false,
        ),
        (
            "FREQ_ERROR_KHZ=-150~150",
            "FREQ_ERROR_KHZ=*E:BT-Offset#",
            "*E:BT-Offset#",
            "-150~150",
            false,
        ),
        (
            "RX_TARGET_POWER=-87",
            "RX_TARGET_POWER=*E:BT-Input#",
            "*E:BT-Input#",
            "-87",
            true,
        ),
        (
            "FRAME_COUNT=500",
            "FRAME_COUNT=*E:BT-Count#",
            "*E:BT-Count#",
            "500",
            true,
        ),
        ("PER=<30.8%", "PER=*E:BT-PER#", "*E:BT-PER#", "<30.8%", true),
    ] {
        let mut arguments = if rx {
            bluetooth_rx_arguments()
        } else {
            bluetooth_plan_arguments()
        };
        replace_plan_script(
            &mut arguments,
            if rx { "BT_RX_HIGH=" } else { "BT_TX_HIGH=" },
            if rx { ";BT_RX_HIGH=" } else { ";BT_TX_HIGH=" },
        );
        if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
            requirements.remove(if rx { 4 } else { 1 });
        }
        replace_plan_script(&mut arguments, from, to);
        arguments["bundle"]["runtime_bindings"] = json!([{"reference":reference,"value":value}]);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][if rx { 3 } else { 0 }]["status"],
            "unknown",
            "{from}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
        assert_eq!(report["validation"]["runtime_verification"], "unchecked");
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_reports_additional_rows_and_excludes_dead_measurements() -> Result<()> {
    use serde_json::json;
    let mut arguments = bluetooth_plan_arguments();
    replace_plan_script(&mut arguments, "100000|QUIT|FAIL", "100000|NEXT|FAIL");
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default();
    arguments["bundle"]["files"][0]["text"] = json!(format!(
        "{text}{}",
        "EXTRA_BT=\"DLLIOT|TX_MULTI_VERIFY|ANT=1&FREQ=2440&TX_TARGET_POWER=20|POWER=-3~1&FREQ_ERROR_KHZ=-150~150|100000|QUIT|FAIL\"\n"
    ));
    let report = plan_report(arguments).await?;
    assert_eq!(report["mandatory"], json!({"total":3,"matched":3}));
    assert_eq!(report["additional"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["additional"][0]["row"], "EXTRA_BT");
    let mut arguments = bluetooth_plan_arguments();
    replace_plan_script(&mut arguments, "20000|NEXT|FAIL", "20000|QUIT|FAIL");
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "missing", "{report}");
    assert_eq!(report["coverage"][1]["status"], "missing", "{report}");
    assert_eq!(report["additional"], json!([]));
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bluetooth_never_ignores_unaudited_dimensions_or_erases_offset_in_exceptions()
-> Result<()> {
    use serde_json::json;
    for (field, value) in [
        ("channel", json!(0)),
        ("bandwidth", json!({"value":2,"unit":"MHz"})),
        ("standard", json!("unreviewed")),
        ("rate", json!("unreviewed")),
        (
            "evm",
            json!({"operator":"lt","threshold":{"value":-35,"unit":"dB"}}),
        ),
    ] {
        let mut arguments = bluetooth_plan_arguments();
        replace_plan_script(&mut arguments, "BT_TX_HIGH=", ";BT_TX_HIGH=");
        if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
            requirements.remove(1);
        }
        arguments["plan"]["requirements"][0]["test"][field] = value;
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], "unknown",
            "{field}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    let mut arguments = bluetooth_conflict_arguments();
    let mut exception = bluetooth_exception(&arguments, 0, 0);
    exception["decision"]["frequency_offset"] = json!(null);
    arguments["plan"]["exceptions"] = json!([exception]);
    let report = plan_report(arguments).await?;
    assert_eq!(
        report["conflicts"][0]["resolved_by"],
        serde_json::Value::Null
    );
    assert_eq!(report["ready_for_review"], false);
    let mut arguments = bluetooth_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["frequency_offset"]["unit"] =
        json!("x".repeat(257));
    assert_eq!(call_plan(arguments).await?.is_error, Some(true));
    Ok(())
}

#[cfg(feature = "mcp")]
fn rx_plan_arguments() -> serde_json::Value {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    arguments["bundle"] = bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "RX=\"DLLWIFI_TEST|RX_VERIFY_PER|BAND=6G&ANT=1,2,4,8&STANDARD=11BE&FREQ=6105&BW=320&DATA_RATE=MCS7&RX_TARGET_POWER=-60dBm&FRAME_COUNT=500|PER=<10%&RSSI=6dB|1|QUIT|FAIL\"\n"
    ));
    arguments["plan"]["requirements"][0] = json!({
        "id":"RX-MCS7", "applicability":"mandatory",
        "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5, RX fixture","excerpt":"500 packets; PER strictly below 10%; RSSI +/-6 dB"}],
        "test":{
            "technology":"wifi", "purpose":"rx", "band":"6G", "standard":"11BE",
            "frequency":{"value":6105,"unit":"MHz"}, "bandwidth":{"value":320,"unit":"MHz"},
            "rate":"MCS7", "chains":{"kind":"per_chain","value":[1,2,4,8]},
            "input_level":{"value":-60,"unit":"dBm"}, "packet_count":500,
            "per":{"operator":"lt","threshold":{"value":10,"unit":"%"}},
            "rssi_tolerance":{"lower":-6,"upper":6,"unit":"dB"}
        }
    });
    arguments
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_rx_matches_sourced_limits_through_public_tool() -> Result<()> {
    let arguments = rx_plan_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["mandatory"],
        serde_json::json!({"total":1,"matched":1})
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "RX");
    assert_eq!(
        report["coverage"][0]["provenance"],
        arguments["plan"]["requirements"][0]["provenance"]
    );
    assert_eq!(report["validation"]["hardware_verification"], "unchecked");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_rx_distinguishes_exact_counts_units_and_acceptance_boundaries() -> Result<()> {
    for (from, to, expected) in [
        ("FRAME_COUNT=500", "FRAME_COUNT=499", "conflicting"),
        ("FRAME_COUNT=500", "FRAME_COUNT=501", "conflicting"),
        ("PER=<10%", "PER=<9.9%", "conflicting"),
        ("PER=<10%", "PER=<10.1%", "conflicting"),
        ("PER=<10%", "PER=<=10%", "unknown"),
        ("PER=<10%", "PER=10%", "unknown"),
        (
            "RX_TARGET_POWER=-60dBm",
            "RX_TARGET_POWER=-60.1dBm",
            "conflicting",
        ),
        (
            "RX_TARGET_POWER=-60dBm",
            "RX_TARGET_POWER=-59.9dBm",
            "conflicting",
        ),
        ("RX_TARGET_POWER=-60dBm", "RX_TARGET_POWER=-60dB", "unknown"),
        ("RSSI=6dB", "RSSI=5.9dB", "conflicting"),
        ("RSSI=6dB", "RSSI=6.1dB", "conflicting"),
        ("RSSI=6dB", "RSSI=-6~6dB", "matched"),
        ("RSSI=6dB", "RSSI=-5.9~6dB", "conflicting"),
        ("RSSI=6dB", "RSSI=-6.1~6dB", "conflicting"),
        ("RSSI=6dB", "RSSI=-6~5.9dB", "conflicting"),
        ("RSSI=6dB", "RSSI=-6~6.1dB", "conflicting"),
        ("RSSI=6dB", "RSSI=6dBm", "unknown"),
        ("FREQ=6105", "FREQ=6100", "conflicting"),
        ("BW=320", "BW=160", "conflicting"),
        ("STANDARD=11BE", "STANDARD=11AX", "conflicting"),
        ("DATA_RATE=MCS7", "DATA_RATE=MCS6", "conflicting"),
        ("ANT=1,2,4,8", "ANT=15", "conflicting"),
    ] {
        let mut arguments = rx_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], expected,
            "{from} -> {to}: {report}"
        );
        assert_eq!(
            report["ready_for_review"],
            expected == "matched",
            "{report}"
        );
    }
    let mut arguments = rx_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["per"]["operator"] = serde_json::json!("le");
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_rx_never_counts_unreachable_runtime_or_unknown_semantics() -> Result<()> {
    for (from, to, expected) in [
        ("RX=", ";RX=", "missing"),
        (
            "RX_TARGET_POWER=-60dBm",
            "RX_TARGET_POWER=*E:Input-Level#",
            "unknown",
        ),
        ("FRAME_COUNT=500", "FRAME_COUNT=*E:Input-Count#", "unknown"),
        ("PER=<10%", "PER=*E:Input-PER#", "unknown"),
        ("RSSI=6dB", "RSSI=*E:Input-RSSI#", "unknown"),
        ("DLLWIFI_TEST|", "DLLWIFI_TEST#UNPROVEN|", "unknown"),
    ] {
        let mut arguments = rx_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], expected,
            "{from} -> {to}: {report}"
        );
        assert_eq!(report["mandatory"]["matched"], 0);
        assert_eq!(report["ready_for_review"], false);
    }
    let mut arguments = rx_plan_arguments();
    replace_plan_script(
        &mut arguments,
        "[RUN]\n",
        "[RUN]\nSTOP=\"DLLWIFI_TEST|RX_VERIFY_PER|BAND=6G&ANT=1,2,4,8&STANDARD=11BE&FREQ=6105&BW=320&DATA_RATE=MCS7&RX_TARGET_POWER=-60dBm&FRAME_COUNT=499|PER=<10%&RSSI=6dB|1|QUIT|FAIL\"\n",
    );
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
    assert_eq!(
        report["coverage"][0]["evidence"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "STOP");
    Ok(())
}

#[cfg(feature = "mcp")]
fn calibration_plan_arguments() -> serde_json::Value {
    use serde_json::json;
    let mut arguments = rx_plan_arguments();
    replace_plan_script(
        &mut arguments,
        "[RUN]\n",
        concat!(
            "[RUN]\n",
            "SETUP=\"SSH|OPEN|fixture@fixture-host|NULL|1|NEXT|FAIL\"\n",
            "CAL=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=1,2,4,8|NULL|1|NEXT|FAIL\"\n"
        ),
    );
    arguments["plan"]["requirements"][0]["depends_on"] = json!(["CAL"]);
    if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
        requirements.push(json!({
            "id":"CAL", "applicability":"mandatory", "depends_on":["SETUP"],
            "provenance":[{"source_id":"plan","revision":"3.8","location":"section 6.5 setup/calibration fixture"}],
            "test":{"technology":"wifi","purpose":"calibration","band":"6G","standard":"11AX",
                "chains":{"kind":"per_chain","value":[1,2,4,8]}}
        }));
        requirements.push(json!({
            "id":"SETUP", "applicability":"mandatory",
            "provenance":[{"source_id":"plan","revision":"3.8","excerpt":"Approved fixture connection before calibration"}],
            "test":{"purpose":"setup","procedure":{"device":"SSH","function":"OPEN","parameters":"fixture@fixture-host","criteria":"NULL"}}
        }));
    }
    arguments
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_proves_declared_success_order_independent_of_plan_list_order()
-> Result<()> {
    let report = plan_report(calibration_plan_arguments()).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["mandatory"],
        serde_json::json!({"total":3,"matched":3})
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "RX");
    assert_eq!(report["coverage"][1]["evidence"][0]["row"], "CAL");
    assert_eq!(report["coverage"][2]["evidence"][0]["row"], "SETUP");
    assert_eq!(report["validation"]["runtime_verification"], "unchecked");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_blocks_wrong_modes_missing_chains_bypasses_and_failed_setup() -> Result<()>
{
    for (from, to) in [
        ("STANDARD=11AX&ANT=1,2,4,8", "STANDARD=11BE&ANT=1,2,4,8"),
        ("STANDARD=11AX&ANT=1,2,4,8", "STANDARD=11AX&ANT=1,2,4"),
        ("CAL=", ";CAL="),
        (
            "fixture@fixture-host|NULL|1|NEXT|FAIL",
            "fixture@fixture-host|NULL|1|RX|CAL",
        ),
        (
            "fixture@fixture-host|NULL|1|NEXT|FAIL",
            "fixture@fixture-host|NULL|1|NEXT|RX",
        ),
        (
            "STANDARD=11AX&ANT=1,2,4,8|NULL|1|NEXT|FAIL",
            "STANDARD=11AX&ANT=1,2,4,8|NULL|1|NEXT|RX",
        ),
        ("fixture@fixture-host", "fixture@wrong-host"),
    ] {
        let mut arguments = calibration_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_ne!(
            report["coverage"][0]["status"], "matched",
            "{from} -> {to}: {report}"
        );
        assert_eq!(report["ready_for_review"], false, "{report}");
        assert!(!report["blockers"].as_array().is_none_or(Vec::is_empty));
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_preserves_two_week_note_without_inventing_operator_history() -> Result<()>
{
    use serde_json::json;
    let mut arguments = calibration_plan_arguments();
    arguments["plan"]["requirements"][1]["test"]["calibration_interval"] =
        json!({"value":2,"unit":"weeks"});
    arguments["plan"]["requirements"][1]["provenance"][0]["excerpt"] =
        json!("Calibrate every two weeks; sourced operator requirement, no history supplied.");
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(
        report["coverage"][1]["test"]["calibration_interval"],
        json!({"value":2.0,"unit":"weeks"})
    );
    assert_eq!(
        report["coverage"][1]["provenance"],
        arguments["plan"]["requirements"][1]["provenance"]
    );
    assert_eq!(report["coverage"][1]["evidence"][0]["row"], "CAL");
    assert_eq!(report["coverage"][1]["status"], "unknown", "{report}");
    assert!(
        report["coverage"][1]["reasons"]
            .to_string()
            .contains("scheduling and calibration history remain unchecked")
    );
    assert_ne!(report["coverage"][0]["status"], "matched");
    assert_eq!(report["ready_for_review"], false);
    assert!(report.get("execution_record").is_none());
    assert!(report.get("schedule").is_none());
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_runtime_and_dead_procedures_cannot_satisfy_dependencies() -> Result<()> {
    for (from, to) in [
        ("STANDARD=11AX", "STANDARD=*E:Calibration-Mode#"),
        (
            "STANDARD=11AX&ANT=1,2,4,8",
            "STANDARD=11AX&ANT=*E:Calibration-Chains#",
        ),
        (
            "fixture@fixture-host|NULL|1|NEXT|FAIL",
            "fixture@fixture-host|NULL|1|RX|FAIL",
        ),
    ] {
        let mut arguments = calibration_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_ne!(report["coverage"][1]["status"], "matched", "{report}");
        assert_ne!(report["coverage"][0]["status"], "matched", "{report}");
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_requires_each_chain_before_measurement_not_just_any_chain() -> Result<()>
{
    let mut arguments = calibration_plan_arguments();
    replace_plan_script(
        &mut arguments,
        "CAL=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=1,2,4,8|NULL|1|NEXT|FAIL\"",
        concat!(
            "CAL=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=1|NULL|1|NEXT|FAIL\"\n",
            "CAL2=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=2|NULL|1|NEXT|RX\"\n",
            "CAL4=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=4|NULL|1|NEXT|FAIL\"\n",
            "CAL8=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=8|NULL|1|NEXT|FAIL\""
        ),
    );
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
    assert_eq!(report["ready_for_review"], false);
    replace_plan_script(
        &mut arguments,
        "ANT=2|NULL|1|NEXT|RX",
        "ANT=2|NULL|1|NEXT|FAIL",
    );
    let report = plan_report(arguments).await?;
    assert_eq!(report["status"], "valid", "{report}");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_calibration_orders_macro_return_evidence_in_its_call_context() -> Result<()> {
    use serde_json::json;
    let mut arguments = calibration_plan_arguments();
    replace_plan_script(
        &mut arguments,
        "CAL=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=11AX&ANT=1,2,4,8|NULL|1|NEXT|FAIL\"",
        "CAL=\"MACRO|CALIBRATE|MODE=11AX|NULL|1|NEXT|FAIL\"",
    );
    if let Some(files) = arguments["bundle"]["files"].as_array_mut() {
        files.push(json!({"name":"MACRO_LIST.ini","text":concat!(
            "[CALIBRATE]\n",
            "MEASURE=\"DLLWIFI_TEST|BRCM_RSSI_CALIBRATION|BAND=6G&STANDARD=*V:Macro-Param_MODE#&ANT=1,2,4,8|NULL|1|QUIT|FAIL\"\n"
        )}));
    }
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["coverage"][1]["evidence"][0]["file"],
        "MACRO_LIST.ini"
    );
    assert!(report["coverage"][1]["evidence"][0]["call_site"].is_string());
    for failed_return in ["PASS", "END"] {
        let mut masked_failure = arguments.clone();
        let body = masked_failure["bundle"]["files"][1]["text"]
            .as_str()
            .unwrap_or_default();
        masked_failure["bundle"]["files"][1]["text"] =
            json!(body.replace("|QUIT|FAIL", &format!("|QUIT|{failed_return}")));
        let report = plan_report(masked_failure).await?;
        assert_eq!(
            report["coverage"][0]["status"], "conflicting",
            "{failed_return}: {report}"
        );
        assert_eq!(report["ready_for_review"], false, "{report}");
    }
    replace_plan_script(
        &mut arguments,
        "MODE=11AX|NULL|1|NEXT|FAIL",
        "MODE=11AX|NULL|1|NEXT|RX",
    );
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_rx_only_requires_rssi_where_applicable_and_never_ignores_other_dimensions()
-> Result<()> {
    let mut arguments = rx_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["rssi_tolerance"] = serde_json::Value::Null;
    replace_plan_script(&mut arguments, "&RSSI=6dB", "");
    let report = plan_report(arguments).await?;
    assert_eq!(report["status"], "valid", "{report}");
    let mut arguments = calibration_plan_arguments();
    arguments["plan"]["requirements"][2]["test"]["packet_count"] = serde_json::json!(500);
    let report = plan_report(arguments).await?;
    assert_ne!(report["coverage"][2]["status"], "matched", "{report}");
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
async fn plan_report(arguments: serde_json::Value) -> Result<serde_json::Value> {
    let result = call_plan(arguments).await?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing plan report".into()))
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_matches_sourced_tx_values_and_executable_locations() -> Result<()> {
    let arguments = tx_plan_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(report["ready_for_review"], true);
    assert_eq!(
        report["mandatory"],
        serde_json::json!({"total":1,"matched":1})
    );
    assert_eq!(
        report["sampling"],
        serde_json::json!({"total":0,"matched":0})
    );
    assert_eq!(
        report["coverage"][0]["provenance"],
        arguments["plan"]["requirements"][0]["provenance"]
    );
    assert_eq!(
        report["coverage"][0]["evidence"][0]["file"],
        "MAIN_FLOW.ini"
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["line"], 4);
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "OFDM6");
    assert_eq!(
        report["validation"]["source_files"],
        arguments["bundle"]["files"]
    );
    assert_eq!(
        report["interpretation_verification"],
        "unchecked_client_interpretation"
    );
    assert_eq!(report["validation"]["hardware_verification"], "unchecked");
    Ok(())
}

#[cfg(feature = "mcp")]
fn tx_conflict_arguments() -> serde_json::Value {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    if let Some(sources) = arguments["plan"]["sources"].as_array_mut() {
        sources.push(json!({
            "id":"example","revision":"later-script","kind":"example","approved":false
        }));
    }
    let plan_statement = arguments["plan"]["requirements"][0]["test"].clone();
    let mut example_statement = plan_statement.clone();
    example_statement["power_target"]["value"] = json!(18);
    example_statement["evm"]["threshold"]["value"] = json!(-5);
    arguments["plan"]["conflicts"] = json!([{
        "id":"OFDM6-plan-example", "requirement_id":"TX-OFDM6", "kind":"plan_example",
        "statements":[
            {"provenance":arguments["plan"]["requirements"][0]["provenance"][0],"test":plan_statement},
            {"provenance":{"source_id":"example","revision":"later-script","location":"TEST_SPEC.ini / 6G_TX_TARGET and 6G_TX_11AG_OFDM6_SPEC","excerpt":"18dBm; EVM -5dB (operator unproven)"},"test":example_statement}
        ]
    }]);
    arguments
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_preserves_source_conflicts_until_current_specific_approval() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_conflict_arguments();
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(
        report["conflicts"][0]["resolved_by"],
        serde_json::Value::Null
    );
    assert_eq!(
        report["conflicts"][0]["conflict"]["statements"][1]["test"]["power_target"]["value"],
        serde_json::json!(18.0)
    );
    let exception = json!({
        "id":"review-1", "conflict_id":"OFDM6-plan-example", "requirement_id":"TX-OFDM6",
        "station":"HH5K Wireless Test_2", "source_revisions":{"plan":"3.8","example":"later-script"},
        "decision":arguments["plan"]["requirements"][0]["test"],
        "rationale":"Keep the controlling plan values for this synthetic fixture.",
        "approver":"fixture reviewer", "approval_evidence":"fixture review record 05"
    });
    for (field, value) in [
        ("requirement_id", json!("unrelated")),
        ("approval_evidence", json!("")),
        ("station", json!("other-station")),
    ] {
        let mut invalid = exception.clone();
        invalid[field] = value;
        arguments["plan"]["exceptions"] = json!([invalid]);
        let report = plan_report(arguments.clone()).await?;
        assert_eq!(report["coverage"][0]["status"], "conflicting", "{report}");
        assert_eq!(
            report["conflicts"][0]["resolved_by"],
            serde_json::Value::Null
        );
    }
    let mut stale = exception.clone();
    stale["source_revisions"]["plan"] = json!("3.7");
    arguments["plan"]["exceptions"] = json!([stale]);
    assert_eq!(
        plan_report(arguments.clone()).await?["coverage"][0]["status"],
        "conflicting"
    );
    arguments["plan"]["exceptions"] = json!([exception]);
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(report["conflicts"][0]["resolved_by"], "review-1");
    assert_eq!(report["ready_for_review"], true);
    arguments["plan"]["conflicts"][0]["kind"] = json!("within_source");
    arguments["plan"]["conflicts"][0]["statements"][1]["provenance"]["source_id"] = json!("plan");
    arguments["plan"]["conflicts"][0]["statements"][1]["provenance"]["revision"] = json!("3.8");
    arguments["plan"]["exceptions"] = json!([]);
    assert_eq!(
        plan_report(arguments).await?["coverage"][0]["status"],
        "conflicting"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_never_matches_unaudited_or_invalid_execution() -> Result<()> {
    for (from, to) in [
        ("DLLWIFI_TEST|", "DLLWIFI_TEST#UNPROVEN|"),
        ("EVM=<-35dB", "EVM=-35dB"),
        ("FREQ=6115", "FREQ=*E:Station-Frequency#"),
        ("BAND=6G", "BAND=6G&BAND=6G"),
    ] {
        let mut arguments = tx_plan_arguments();
        let original = arguments["bundle"]["files"][0]["text"]
            .as_str()
            .unwrap_or_default();
        arguments["bundle"]["files"][0]["text"] = serde_json::json!(original.replace(from, to));
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], "unknown",
            "{from} -> {to}: {report}"
        );
        assert_eq!(report["mandatory"]["matched"], 0);
        assert_eq!(report["ready_for_review"], false);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_redacts_review_evidence_without_mutating_supplied_source() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_conflict_arguments();
    arguments["bundle"]["sensitive_values"] = json!(["fixture-secret", "OFDM6"]);
    arguments["plan"]["station"] = json!("fixture-secret station");
    arguments["plan"]["requirements"][0]["provenance"][0]["excerpt"] =
        json!("fixture-secret supplied note");
    let mut report = plan_report(arguments.clone()).await?;
    assert_eq!(
        report["validation"]["source_files"],
        arguments["bundle"]["files"]
    );
    report["validation"] = serde_json::Value::Null;
    let summary = report.to_string();
    assert!(!summary.contains("fixture-secret"), "{summary}");
    assert!(!summary.contains("OFDM6"), "{summary}");
    let report = plan_report(tx_plan_arguments()).await?;
    assert_eq!(
        report["coverage"][0]["status"], "matched",
        "sensitive state leaked between requests: {report}"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_redacts_secrets_discovered_through_static_aliases() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    if let Some(files) = arguments["bundle"]["files"].as_array_mut() {
        files.push(json!({"name":"Settings.ini","text":"[Settings]\nKey=resolved-fixture-secret\nPASSWORD=*V:Settings-Key#\n"}));
    }
    arguments["plan"]["requirements"][0]["provenance"][0]["excerpt"] =
        json!("review note resolved-fixture-secret");
    let mut report = plan_report(arguments).await?;
    report["validation"] = serde_json::Value::Null;
    assert!(
        !report.to_string().contains("resolved-fixture-secret"),
        "{report}"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_rejects_oversized_dimensions_before_diagnostic_expansion() -> Result<()> {
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["rate"] = serde_json::json!("x".repeat(900_000));
    let result = call_plan(arguments).await?;
    assert_eq!(
        result.is_error,
        Some(true),
        "oversized dimensions must be rejected before analysis"
    );
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .map(|value| &value["error"]["code"]),
        Some(&serde_json::json!("invalid_input"))
    );
    Ok(())
}

#[cfg(feature = "mcp")]
fn replace_plan_script(arguments: &mut serde_json::Value, from: &str, to: &str) {
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default();
    arguments["bundle"]["files"][0]["text"] = serde_json::json!(text.replace(from, to));
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_correct_labels_cannot_hide_wrong_dimensions_limits_or_chains() -> Result<()> {
    for (from, to) in [
        ("FREQ=6115", "FREQ=6116"),
        ("BW=20", "BW=40"),
        ("STANDARD=11AG", "STANDARD=11AX"),
        ("DATA_RATE=OFDM6", "DATA_RATE=MCS0"),
        ("TX_TARGET_POWER=15.5dBm", "TX_TARGET_POWER=18dBm"),
        ("POWER=-1~2dB", "POWER=-2~1dB"),
        ("EVM=<-35dB", "EVM=<-34.9dB"),
        ("FRAME_COUNT=500", "FRAME_COUNT=499"),
        ("ANT=1,2,4,8", "ANT=15"),
        ("ANT=1,2,4,8", "ANT=1,2,4"),
    ] {
        let mut arguments = tx_plan_arguments();
        replace_plan_script(&mut arguments, from, to);
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], "conflicting",
            "{from} -> {to}: {report}"
        );
        assert_eq!(report["status"], "invalid");
        assert_eq!(report["mandatory"]["matched"], 0);
    }
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["evm"]["operator"] = serde_json::json!("le");
    assert_eq!(
        plan_report(arguments).await?["coverage"][0]["status"],
        "conflicting"
    );
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["test"]["power_target"]["unit"] = serde_json::json!("dB");
    assert_eq!(
        plan_report(arguments).await?["coverage"][0]["status"],
        "conflicting"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_keeps_unsupported_requirements_and_missing_source_facts_unknown() -> Result<()> {
    use serde_json::json;
    for (field, value) in [
        ("technology", json!("bluetooth")),
        ("purpose", json!("rx")),
        ("band", json!("5G")),
        ("standard", serde_json::Value::Null),
        ("frequency", serde_json::Value::Null),
        ("channel", json!(33)),
        ("chains", json!({"kind":"count","value":4})),
    ] {
        let mut arguments = tx_plan_arguments();
        arguments["plan"]["requirements"][0]["test"][field] = value;
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], "unknown",
            "{field}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
    }
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["provenance"][0]["revision"] = json!("");
    assert_eq!(
        plan_report(arguments).await?["coverage"][0]["status"],
        "unknown"
    );
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["depends_on"] = json!(["SETUP"]);
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "unknown");
    assert_eq!(report["coverage"][0]["depends_on"], json!(["SETUP"]));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_excludes_comments_dead_rows_and_separates_additional_cases() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    let row = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .lines()
        .last()
        .unwrap_or_default()
        .to_string();
    let dead = row.replace("OFDM6=", "DEAD=");
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    arguments["bundle"]["files"][0]["text"] = json!(format!("{text}{dead}\n;{dead}\n"));
    replace_plan_script(&mut arguments, "FREQ=6115", "FREQ=6116");
    let report = plan_report(arguments).await?;
    assert_eq!(report["mandatory"]["matched"], 0);
    assert_eq!(
        report["coverage"][0]["evidence"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["row"], "OFDM6");
    assert_eq!(report["additional"], json!([]));
    let mut arguments = tx_plan_arguments();
    arguments["bundle"]["files"][0]["text"] = json!(format!(
        "{}{}\n",
        text.replace("|QUIT|FAIL", "|NEXT|FAIL"),
        row.replace("OFDM6=", "EXTRA=")
            .replace("FREQ=6115", "FREQ=6175")
    ));
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(report["additional"][0]["row"], "EXTRA");
    let mut arguments = tx_plan_arguments();
    replace_plan_script(&mut arguments, "OFDM6=", ";OFDM6=");
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "missing");
    assert_eq!(report["mandatory"]["matched"], 0);
    assert_eq!(report["ready_for_review"], false);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_keeps_unrelated_operating_points_additional_when_requirement_is_missing() -> Result<()>
{
    for label in ["UNRELATED", "OFDM6"] {
        let mut arguments = tx_plan_arguments();
        replace_plan_script(&mut arguments, "OFDM6=", &format!("{label}="));
        replace_plan_script(&mut arguments, "FREQ=6115", "FREQ=6175");
        replace_plan_script(&mut arguments, "DATA_RATE=OFDM6", "DATA_RATE=MCS11");
        let report = plan_report(arguments).await?;
        assert_eq!(report["coverage"][0]["status"], "missing", "{report}");
        assert_eq!(report["mandatory"]["matched"], 0);
        assert_eq!(report["ready_for_review"], false);
        assert_eq!(report["coverage"][0]["evidence"], serde_json::json!([]));
        assert_eq!(report["additional"].as_array().map(Vec::len), Some(1));
        assert_eq!(report["additional"][0]["row"], label);
        assert_eq!(report["additional"][0]["line"], 4);
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_never_excludes_unaudited_dispatch_as_an_unrelated_case() -> Result<()> {
    for (mode, expected) in [
        ("UNPROVEN", "unknown"),
        ("QUICK", "missing"),
        ("PROXY", "missing"),
    ] {
        let mut arguments = tx_plan_arguments();
        replace_plan_script(
            &mut arguments,
            "DLLWIFI_TEST|",
            &format!("DLLWIFI_TEST#{mode}|"),
        );
        replace_plan_script(&mut arguments, "FREQ=6115", "FREQ=6175");
        replace_plan_script(&mut arguments, "DATA_RATE=OFDM6", "DATA_RATE=MCS11");
        let report = plan_report(arguments).await?;
        assert_eq!(
            report["coverage"][0]["status"], expected,
            "{mode}: {report}"
        );
        assert_eq!(report["ready_for_review"], false);
        if expected == "unknown" {
            assert_eq!(report["coverage"][0]["evidence"][0]["line"], 4);
            assert_eq!(report["additional"], serde_json::json!([]));
        } else {
            assert_eq!(report["additional"].as_array().map(Vec::len), Some(1));
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_reports_selected_flow_mandatory_and_sampling_denominators() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    let mut sampling = arguments["plan"]["requirements"][0].clone();
    sampling["id"] = json!("TX-SAMPLING");
    sampling["applicability"] = json!("sampling");
    sampling["test"]["rate"] = json!("MCS11");
    if let Some(requirements) = arguments["plan"]["requirements"].as_array_mut() {
        requirements.push(sampling);
    }
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["mandatory"], json!({"total":1,"matched":1}));
    assert_eq!(report["sampling"], json!({"total":0,"matched":0}));
    arguments["flow_variant"] = json!("sampling");
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["sampling"], json!({"total":1,"matched":0}));
    assert_eq!(report["ready_for_review"], false);
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let sampling_row = text
        .lines()
        .last()
        .unwrap_or_default()
        .replace("OFDM6=", "SAMPLE=")
        .replace("DATA_RATE=OFDM6", "DATA_RATE=MCS11");
    arguments["bundle"]["files"][0]["text"] = json!(format!(
        "{}{sampling_row}\n",
        text.replace("|QUIT|FAIL", "|NEXT|FAIL")
    ));
    let report = plan_report(arguments).await?;
    assert_eq!(report["mandatory"], json!({"total":1,"matched":1}));
    assert_eq!(report["sampling"], json!({"total":1,"matched":1}));
    assert_eq!(report["ready_for_review"], false, "{report}");
    assert_eq!(report["sampling_policy"]["status"], "unresolved");
    assert!(
        report["blockers"]
            .to_string()
            .contains("sampling rate and schedule")
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_combines_individual_chain_evidence_without_counting_composite_masks() -> Result<()> {
    let mut arguments = tx_plan_arguments();
    let text = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let row = text.lines().last().unwrap_or_default();
    let mut individual = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n".to_string();
    for (index, mask) in std::iter::repeat_n(1, 65).chain([2, 4, 8]).enumerate() {
        individual.push_str(
            &row.replace("OFDM6=", &format!("CHAIN{index}="))
                .replace("ANT=1,2,4,8", &format!("ANT={mask}"))
                .replace(
                    "|QUIT|FAIL",
                    if mask == 8 {
                        "|QUIT|FAIL"
                    } else {
                        "|NEXT|FAIL"
                    },
                ),
        );
        individual.push('\n');
    }
    arguments["bundle"]["files"][0]["text"] = serde_json::json!(individual);
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(
        report["coverage"][0]["evidence"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(report["additional"], serde_json::json!([]));
    replace_plan_script(&mut arguments, "ANT=8", "ANT=15");
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting");
    assert_eq!(report["mandatory"]["matched"], 0);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_comparison_budget_never_reports_partial_analysis_as_ready() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    let source = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let row = source.lines().last().unwrap_or_default();
    let mut text = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n".to_string();
    for index in 0..257 {
        text.push_str(&row.replace("OFDM6=", &format!("TX{index}=")).replace(
            "|QUIT|FAIL",
            if index == 256 {
                "|QUIT|FAIL"
            } else {
                "|NEXT|FAIL"
            },
        ));
        text.push('\n');
    }
    let original = arguments["plan"]["requirements"][0].clone();
    arguments["plan"]["requirements"] = json!(
        (0..256)
            .map(|index| {
                let mut requirement = original.clone();
                requirement["id"] = json!(format!("TX-{index}"));
                requirement
            })
            .collect::<Vec<_>>()
    );
    arguments["bundle"]["files"][0]["text"] = json!(text);
    let report = plan_report(arguments).await?;
    assert_eq!(
        report["status"], "incomplete",
        "budget exhaustion was hidden"
    );
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(report["coverage"][255]["status"], "unknown");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_accepts_source_locations_or_prompt_excerpts_and_rejects_neither() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["requirements"][0]["provenance"][0]["excerpt"] = json!("");
    assert_eq!(
        plan_report(arguments.clone()).await?["coverage"][0]["status"],
        "matched"
    );
    arguments["plan"]["sources"][0]["kind"] = json!("prompt");
    arguments["plan"]["requirements"][0]["provenance"][0]["location"] = json!("");
    arguments["plan"]["requirements"][0]["provenance"][0]["excerpt"] =
        json!("Reviewed prompt: measure this TX case.");
    assert_eq!(
        plan_report(arguments.clone()).await?["coverage"][0]["status"],
        "matched"
    );
    arguments["plan"]["requirements"][0]["provenance"][0]["excerpt"] = json!("");
    assert_eq!(
        plan_report(arguments).await?["coverage"][0]["status"],
        "unknown"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_uses_macro_call_evidence_without_borrowing_another_calls_values() -> Result<()> {
    use serde_json::json;
    let mut arguments = tx_plan_arguments();
    let macro_row = arguments["bundle"]["files"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .lines()
        .last()
        .unwrap_or_default()
        .replace("FREQ=6115", "FREQ=*V:Macro-Param_FREQ#");
    arguments["bundle"]["files"] = json!([
        {"name":"MAIN_FLOW.ini","text":"[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"MACRO|MEASURE|FREQ=6115|NULL|1|NEXT|FAIL\"\nB=\"MACRO|MEASURE|FREQ=6175|NULL|1|QUIT|FAIL\"\n"},
        {"name":"MACRO_LIST.ini","text":format!("[MEASURE]\n{macro_row}\n")}
    ]);
    let report = plan_report(arguments.clone()).await?;
    assert_eq!(report["coverage"][0]["status"], "matched", "{report}");
    assert_eq!(
        report["coverage"][0]["evidence"][0]["file"],
        "MACRO_LIST.ini"
    );
    assert_eq!(report["coverage"][0]["evidence"][0]["line"], 2);
    assert_eq!(report["coverage"][0]["evidence"][0]["call_site"], "row:0");
    assert_eq!(report["additional"][0]["call_site"], "row:1");
    arguments["plan"]["requirements"][0]["test"]["frequency"]["value"] = json!(6335);
    let report = plan_report(arguments).await?;
    assert_eq!(report["coverage"][0]["status"], "conflicting");
    assert_eq!(report["mandatory"]["matched"], 0);
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn plan_bounds_and_source_authority_never_turn_into_success() -> Result<()> {
    use serde_json::json;
    for invalid in 0..5 {
        let mut arguments = tx_plan_arguments();
        let requirement = arguments["plan"]["requirements"][0].clone();
        match invalid {
            0 => arguments["plan"]["requirements"] = json!([requirement.clone(), requirement]),
            1 => {
                arguments["plan"]["requirements"] = json!(
                    (0..257)
                        .map(|index| {
                            let mut next = requirement.clone();
                            next["id"] = json!(format!("TX-{index}"));
                            next
                        })
                        .collect::<Vec<_>>()
                )
            }
            2 => {
                arguments["plan"]["requirements"][0]["test"]["chains"] =
                    json!({"kind":"per_chain","value":vec![1;17]})
            }
            3 => arguments["plan"]["unresolved_questions"] = json!(["x".repeat(1_048_576)]),
            _ => arguments["bundle"]["files"][0]["name"] = json!("../MAIN_FLOW.ini"),
        }
        let result = call_plan(arguments).await?;
        assert_eq!(result.is_error, Some(true), "{invalid}: {result:?}");
        assert_eq!(
            result
                .structured_content
                .as_ref()
                .map(|value| &value["error"]["code"]),
            Some(&json!("invalid_input"))
        );
    }
    for field in ["approved", "revision", "kind"] {
        let mut arguments = tx_plan_arguments();
        arguments["plan"]["sources"][0][field] = match field {
            "approved" => json!(false),
            "revision" => json!("old"),
            _ => json!("example"),
        };
        let report = plan_report(arguments).await?;
        assert_eq!(report["ready_for_review"], false);
        assert_eq!(report["coverage"][0]["status"], "unknown");
    }
    let mut arguments = tx_plan_arguments();
    arguments["plan"]["unresolved_questions"] = json!(["Which approved station routing applies?"]);
    let report = plan_report(arguments).await?;
    assert_eq!(report["ready_for_review"], false);
    assert_eq!(
        report["blockers"][0],
        "Which approved station routing applies?"
    );
    let engine = Engine::new(tx_plan_snapshot());
    assert!(!engine.list_functions(Some("DLLWIFI_TEST"))?[0].composition_supported);
    Ok(())
}

#[cfg(feature = "mcp")]
async fn call_bundle(arguments: serde_json::Value) -> Result<rmcp::model::CallToolResult> {
    let request = serde_json::from_value(arguments)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(MemoryCatalog))
        .validate_ini_bundle(rmcp::handler::server::wrapper::Parameters(request))
        .await
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))
}

#[cfg(feature = "mcp")]
async fn bundle_report(arguments: serde_json::Value) -> Result<serde_json::Value> {
    let result = call_bundle(arguments).await?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing bundle result".into()))
}

#[cfg(feature = "mcp")]
async fn bundle_report_with_snapshot(
    arguments: serde_json::Value,
    snapshot: Snapshot,
) -> Result<serde_json::Value> {
    struct SnapshotCatalog(Snapshot);
    impl script_audit_mcp::Catalog for SnapshotCatalog {
        fn snapshot(&self) -> Result<Snapshot> {
            Ok(self.0.clone())
        }
    }
    let request = serde_json::from_value(arguments)
        .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let result =
        script_audit_mcp::mcp::McpServer::new(std::sync::Arc::new(SnapshotCatalog(snapshot)))
            .validate_ini_bundle(rmcp::handler::server::wrapper::Parameters(request))
            .await
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing bundle result".into()))
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_keeps_function_identity_scope_overrides_and_global_fallback() -> Result<()>
{
    let mut snapshot = fixture_snapshot();
    for (source, interface) in [("BUILT-IN", "WIFI_TEST"), ("DLL", "OTHER")] {
        let mut function = snapshot.functions[1].clone();
        function.source = source.into();
        function.interface = interface.into();
        snapshot.functions.push(function);
    }
    snapshot.parameter_definitions[0].device_name.clear();
    snapshot.parameter_links[0].device_name.clear();
    for (scope, allowed) in [("STATION_A", "{7}"), ("UNRELATED", "{99}")] {
        let mut definition = snapshot.parameter_definitions[0].clone();
        definition.device_name = scope.into();
        definition.allowed_values = allowed.into();
        snapshot.parameter_definitions.push(definition);
        let mut link = snapshot.parameter_links[0].clone();
        link.device_name = scope.into();
        snapshot.parameter_links.push(link);
    }
    snapshot.criteria_links[0].device_name.clear();
    let mut criterion = snapshot.criteria_links[0].clone();
    criterion.device_name = "STATION_A".into();
    snapshot.criteria_links.push(criterion);
    for (device, scope, ant, expected) in [
        ("DLLWIFI_TEST#PROXY", Some("STATION_A"), "7", "valid"),
        ("DLLWIFI_TEST#PROXY", Some("STATION_A"), "15", "invalid"),
        ("DLLWIFI_TEST", None, "15,2", "valid"),
        ("DLLWIFI_TEST", Some("UNLISTED"), "15,2", "valid"),
        ("DLLWIFI_TEST", Some("UNLISTED"), "99", "invalid"),
        ("WIFI_TEST", None, "15", "incomplete"),
        ("DLLOTHER", None, "15", "incomplete"),
        ("DLLABSENT", None, "15", "invalid"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"{device}|TX_MULTI_VERIFICATION|ANT={ant}|POWER=5dB|0|QUIT|FAIL\"\n"
        );
        let mut arguments = bundle_arguments(&text);
        arguments["device_scope"] = serde_json::json!(scope);
        let report = bundle_report_with_snapshot(arguments, snapshot.clone()).await?;
        assert_eq!(report["layers"]["catalog"], expected, "{report}");
        assert_eq!(report["script_sections"][0]["rows"][0]["device"], device);
    }
    let mut ambiguous = snapshot;
    ambiguous.functions.push(ambiguous.functions[1].clone());
    let report = bundle_report_with_snapshot(
        bundle_arguments(concat!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
            "A=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15|NULL|1|QUIT|FAIL\"\n"
        )),
        ambiguous,
    )
    .await?;
    assert_eq!(report["layers"]["catalog"], "invalid", "{report}");
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "ambiguous_function")
    }));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_requiredness_constraints_and_unknown_criteria_are_explicit() -> Result<()> {
    for (parameters, criteria, expected, code) in [
        ("NULL", "NULL", "invalid", "required"),
        ("ANT=15", "POWER=11dB", "invalid", "allowed_values"),
        ("ANT=x", "POWER=5dB", "invalid", "type_violation"),
        ("ANT=15,", "NULL", "invalid", "invalid_value"),
        ("ANT=15", "POWER=5", "invalid", "pattern_violation"),
        ("ANT=15&ANT=2", "NULL", "invalid", "duplicate_key"),
        ("ANT=15&", "NULL", "invalid", "invalid_assignment"),
        ("ANT=15", "UNKNOWN=5", "incomplete", "unknown_criteria_key"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|{parameters}|{criteria}|1|QUIT|FAIL\"\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["catalog"], expected, "{report}");
        assert_eq!(report["source_files"][0]["text"], text);
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(
                    |issues| issues.iter().any(|issue| issue["layer"] == "catalog"
                        && issue["code"] == code
                        && issue["line"] == 4)
                ),
            "{report}"
        );
    }
    let mut snapshot = fixture_snapshot();
    snapshot.parameter_links[0].required = false;
    snapshot.parameter_definitions[0].required = true;
    let text = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|NULL|NULL|1|QUIT|FAIL\"\n";
    let report = bundle_report_with_snapshot(bundle_arguments(text), snapshot.clone()).await?;
    assert_eq!(report["layers"]["catalog"], "valid", "{report}");
    assert_eq!(report["execution"][0]["parameters"], "NULL");
    snapshot.criteria_links[0].required = true;
    let report = bundle_report_with_snapshot(bundle_arguments(text), snapshot).await?;
    assert_eq!(report["layers"]["catalog"], "invalid", "{report}");
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "required" && issue["field"] == "criteria.POWER")
    }));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_orphans_and_unsupported_knowledge_never_pass_or_fill_defaults() -> Result<()>
{
    let text = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15|NULL|1|QUIT|FAIL\"\n";
    for (change, code) in [
        ("orphan", "missing_definition"),
        ("wrong_scope", "missing_definition"),
        ("type", "unsupported_type"),
        ("cardinality", "unsupported_cardinality"),
        ("pattern", "unsupported_pattern"),
        ("constraint", "unsupported_constraint"),
        ("profile", "unsupported_grammar"),
    ] {
        let mut snapshot = fixture_snapshot();
        match change {
            "orphan" => {
                snapshot.parameter_definitions.remove(0);
            }
            "wrong_scope" => snapshot.parameter_definitions[0].device_name = "UNRELATED".into(),
            "type" => snapshot.parameter_definitions[0].kind = "opaque".into(),
            "cardinality" => snapshot.parameter_definitions[0].cardinality = "UNKNOWN".into(),
            "pattern" => snapshot.parameter_definitions[0].value_pattern = "[<optional>]".into(),
            "constraint" => {
                snapshot.parameter_definitions[0].allowed_values = "unreviewed prose".into()
            }
            "profile" => snapshot.functions[1].convention = None,
            _ => unreachable!(),
        }
        let report = bundle_report_with_snapshot(bundle_arguments(text), snapshot.clone()).await?;
        assert_eq!(
            report["layers"]["catalog"], "incomplete",
            "{change}: {report}"
        );
        assert_eq!(report["status"], "incomplete", "{change}: {report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code
                    && issue["severity"] == "unsupported"
                    && issue["file"] == "MAIN_FLOW.ini"
                    && issue["line"] == 4)),
            "{report}"
        );
        let missing = text.replace("ANT=15", "NULL");
        let report = bundle_report_with_snapshot(bundle_arguments(&missing), snapshot).await?;
        assert_eq!(report["status"], "invalid", "{change}: {report}");
        assert_eq!(report["execution"][0]["parameters"], "NULL");
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_schema_uncertainty_preserves_assignment_errors() -> Result<()> {
    let mut snapshot = fixture_snapshot();
    snapshot
        .parameter_links
        .push(snapshot.parameter_links[0].clone());
    for (parameters, criteria) in [
        ("ANT=15&ANT=2", "NULL"),
        ("ANT=15&ANT=*E:Station-Ant#", "NULL"),
        ("ANT=*E:Station-Ant#&ANT=15", "NULL"),
        ("ANT=15", "POWER=5dB&POWER=*E:Station-Power#"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|{parameters}|{criteria}|1|QUIT|FAIL\"\n"
        );
        let report = bundle_report_with_snapshot(bundle_arguments(&text), snapshot.clone()).await?;
        assert_eq!(report["status"], "invalid", "{report}");
        for code in ["knowledge_error", "duplicate_key"] {
            assert!(
                report["diagnostics"].as_array().is_some_and(|issues| issues
                    .iter()
                    .any(|issue| issue["layer"] == "catalog" && issue["code"] == code)),
                "{report}"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_checks_resolved_macro_contexts_static_values_and_raw_payloads() -> Result<()>
{
    let main = concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "A=\"MACRO|MEASURE|ANTS=15,2|LIMIT=5dB|1|NEXT|FAIL\"\n",
        "B=\"MACRO|MEASURE|ANTS=999|LIMIT=5dB|1|QUIT|FAIL\"\n"
    );
    let mut arguments = bundle_arguments(main);
    arguments["files"].as_array_mut().ok_or_else(|| script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"MACRO_LIST.ini", "text":concat!(
            "[MEASURE]\n",
            "TX=\"DLLWIFI_TEST#QUICK|TX_MULTI_VERIFICATION|ANT=*V:Macro-Param_ANTS#|POWER=*V:Macro-Criteria_LIMIT#|0|PASS|FAIL\"\n"
        )}));
    let report = bundle_report(arguments).await?;
    assert_eq!(report["layers"]["references"], "valid", "{report}");
    assert_eq!(report["layers"]["catalog"], "invalid", "{report}");
    let errors = report["diagnostics"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("missing diagnostics".into()))?
        .iter()
        .filter(|issue| issue["layer"] == "catalog" && issue["severity"] == "error")
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), 1, "{report}");
    assert_eq!(errors[0]["code"], "allowed_values");
    assert_eq!(errors[0]["file"], "MACRO_LIST.ini");
    assert_eq!(errors[0]["line"], 2);
    assert_eq!(errors[0]["row"], "TX");
    assert!(
        errors[0]["evidence"]
            .as_str()
            .is_some_and(|evidence| evidence.contains("call_site=row:1")),
        "{report}"
    );
    let text = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|*V:Settings#|POWER=5dB|NULL|QUIT|FAIL\"\n";
    let mut arguments = bundle_arguments(text);
    arguments["files"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"SETTINGS.ini", "text":"[Settings]\nANT=15,2\n"}));
    let report = bundle_report(arguments).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(
        report["script_sections"][0]["rows"][0]["parameters"],
        "*V:Settings#"
    );
    let raw = "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"SSH|OPEN|DUT@echo a=b&next|root#|NULL|QUIT|FAIL\"\n";
    let report = bundle_report(bundle_arguments(raw)).await?;
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(report["source_files"][0]["text"], raw);
    assert_eq!(
        fixture()
            .validate_line("SSH|OPEN|DUT@echo a=b&next|root#|5000", None)?
            .status,
        ValidationStatus::Valid
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_keeps_unaudited_dispatch_suffixes_incomplete() -> Result<()> {
    for (mode, ant, expected) in [
        ("UNPROVEN", "15", "incomplete"),
        ("UNPROVEN", "999", "invalid"),
        ("*E:Station-Mode#", "999", "invalid"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST#{mode}|TX_MULTI_VERIFICATION|ANT={ant}|NULL|1|QUIT|FAIL\"\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["structure"], "incomplete", "{report}");
        assert_eq!(report["layers"]["catalog"], expected, "{report}");
        assert_eq!(report["status"], expected, "{report}");
        assert_eq!(report["source_files"][0]["text"], text);
        assert_eq!(
            report["execution"][0]["device"],
            format!("DLLWIFI_TEST#{mode}")
        );
    }
    assert!(
        fixture()
            .get_function("DLLWIFI_TEST#UNPROVEN", "TX_MULTI_VERIFICATION", None)
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_rejects_literal_assignment_syntax_around_unknown_values() -> Result<()> {
    for (parameters, criteria) in [
        ("ANT=15", "POWER=*E:Station-Power#=5dB"),
        ("ANT=*E:Station-Ant#=15", "NULL"),
        ("ANT =*E:Station-Ant#", "NULL"),
        ("ANT=15", "*E:Station-Key#=5=bad"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|{parameters}|{criteria}|1|QUIT|FAIL\"\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["catalog"], "invalid", "{report}");
        assert_eq!(report["status"], "invalid", "{report}");
        assert!(
            report["diagnostics"].as_array().is_some_and(|issues| {
                issues.iter().any(|issue| {
                    issue["code"] == "invalid_assignment" && issue["severity"] == "error"
                })
            }),
            "{report}"
        );
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_checks_real_parameter_and_criteria_positions() -> Result<()> {
    let text = concat!(
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n",
        "A = \"DLLWIFI_TEST#QUICK|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|20000|QUIT|FAIL|ERRCODE:opaque\"\n"
    );
    let report = bundle_report(bundle_arguments(text)).await?;
    assert_eq!(report["layers"]["catalog"], "valid", "{report}");
    assert_eq!(report["status"], "valid", "{report}");
    assert_eq!(report["source_files"][0]["text"], text);
    assert_eq!(
        report["script_sections"][0]["rows"][0]["parameters"],
        "ANT=15,2"
    );
    assert_eq!(
        report["script_sections"][0]["rows"][0]["criteria"],
        "POWER=5dB"
    );
    assert_eq!(report["execution"][0]["device"], "DLLWIFI_TEST#QUICK");
    let swapped = text.replace("ANT=15,2|POWER=5dB", "POWER=5dB|ANT=15,2");
    let report = bundle_report(bundle_arguments(&swapped)).await?;
    assert_eq!(report["layers"]["catalog"], "invalid", "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(
                |issues| issues.iter().any(|issue| issue["layer"] == "catalog"
                    && issue["code"] == "unknown_parameter"
                    && issue["file"] == "MAIN_FLOW.ini"
                    && issue["line"] == 4
                    && issue["section"] == "RUN"
                    && issue["row"] == "A")
            )
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_catalog_defers_dynamic_values_without_hiding_literal_errors() -> Result<()> {
    for (parameters, criteria, expected) in [
        ("ANT=*E:Station-Ant#", "POWER=5dB", "incomplete"),
        ("ANT=*V:Absent-Ant#", "POWER=5dB", "incomplete"),
        ("*E:Station-Parameters#", "POWER=5dB", "incomplete"),
        ("ANT=999,*E:Station-Ant#", "POWER=5dB", "invalid"),
        ("ANT=*E:Station-Ant#", "POWER=11dB", "invalid"),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLLWIFI_TEST|TX_MULTI_VERIFICATION|{parameters}|{criteria}|NULL|QUIT|FAIL\"\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["catalog"], expected, "{report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(
                    |issues| issues.iter().any(|issue| issue["layer"] == "catalog"
                        && issue["code"] == "CATALOG_VALUE_UNCHECKED"
                        && issue["severity"] == "unsupported"
                        && issue["line"] == 4)
                ),
            "{report}"
        );
        if expected == "invalid" {
            assert_eq!(report["status"], "invalid", "{report}");
            assert!(
                report["diagnostics"].as_array().is_some_and(|issues| issues
                    .iter()
                    .any(|issue| issue["layer"] == "catalog" && issue["code"] == "allowed_values")),
                "{report}"
            );
        }
    }
    let report = bundle_report(bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "A=\"*E:Station-Device#|TX_MULTI_VERIFICATION|ANT=15|NULL|1|QUIT|FAIL\"\n"
    )))
    .await?;
    assert_eq!(report["layers"]["catalog"], "incomplete", "{report}");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_resolves_supplied_static_references_and_locates_missing_keys() -> Result<()> {
    let text = "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|*V:Settings-Channel#|NULL|1|QUIT|FAIL\"\n";
    let mut arguments = bundle_arguments(text);
    arguments["files"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"SETTINGS.ini","text":"[Settings]\nChannel = \"6115\"\n"}));
    let report = bundle_report(arguments.clone()).await?;
    assert_eq!(report["layers"]["references"], "valid", "{report}");
    assert_eq!(report["execution"][0]["parameters"], "6115");
    assert_eq!(report["execution"][0]["reachability"], "reachable");
    assert_eq!(report["source_files"][0]["text"], text);
    arguments["files"][1]["text"] = "[Settings]\nOther = \"0\"\n".into();
    let report = bundle_report(arguments).await?;
    assert_eq!(report["layers"]["references"], "invalid", "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| issue["code"]
                == "REFERENCE_KEY_MISSING"
                && issue["file"] == "MAIN_FLOW.ini"
                && issue["line"] == 4
                && issue["section"] == "RUN"
                && issue["row"] == "A"
                && issue["field"] == "parameters"))
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_macro_calls_keep_arguments_returns_and_reachability_separate() -> Result<()> {
    let mut arguments = bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\nAFTER = \"AFTER\"\n[RUN]\n",
        "FIRST = \"MACRO|MEASURE|CHANNEL=6115|LIMIT=-35|1|SECOND|FIRST_FAIL\"\n",
        "SECOND = \"MACRO|MEASURE|CHANNEL=6275|LIMIT=-32|1|NEXT|SECOND_FAIL\"\n",
        "FIRST_FAIL = \"DLL|CLEAN_FIRST|NULL|NULL|1|FAIL|FAIL\"\n",
        "SECOND_FAIL = \"DLL|CLEAN_SECOND|NULL|NULL|1|FAIL|FAIL\"\n",
        "DEAD = \"DLL|NOT_COVERAGE|NULL|NULL|1|PASS|FAIL\"\n",
        "; COMMENTED = \"DLL|NOT_COVERAGE|NULL|NULL|1|PASS|FAIL\"\n",
        "[AFTER]\nDONE = \"DLL|SAVE|NULL|NULL|1|NEXT|FAIL\"\n",
    ));
    arguments["files"].as_array_mut().ok_or_else(||
        script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"MACRO_LIST.ini","text":
            "[MEASURE]\nREAD = \"DLL|MEASURE|*V:Macro-Param_CHANNEL#|POWER=*V:Macro-Criteria_LIMIT#|1|QUIT|FAIL\"\n"
        }));
    let report = bundle_report(arguments).await?;
    assert_eq!(report["layers"]["references"], "valid", "{report}");
    assert_eq!(report["layers"]["control_flow"], "valid", "{report}");
    let rows = report["execution"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("execution evidence missing".into()))?;
    let reads: Vec<_> = rows
        .iter()
        .filter(|row| row["function"] == "MEASURE" && row["device"] == "DLL")
        .collect();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0]["parameters"], "6115");
    assert_eq!(reads[1]["parameters"], "6275");
    assert_eq!(reads[0]["criteria"], "POWER=-35");
    assert_eq!(reads[1]["criteria"], "POWER=-32");
    assert_ne!(reads[0]["call_site"], reads[1]["call_site"]);
    assert!(reads.iter().all(|row| row["reachability"] == "reachable"));
    assert!(
        rows.iter()
            .any(|row| row["row"] == "DEAD" && row["reachability"] == "unreachable")
    );
    assert!(!rows.iter().any(|row| row["row"] == "COMMENTED"));
    let edges = report["execution_edges"]
        .as_array()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("execution edges missing".into()))?;
    let first_fail = rows
        .iter()
        .find(|row| row["row"] == "FIRST_FAIL")
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("first failure row missing".into()))?;
    let second_fail = rows
        .iter()
        .find(|row| row["row"] == "SECOND_FAIL")
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("second failure row missing".into()))?;
    assert!(edges.iter().any(|edge| edge["source"] == reads[0]["id"]
        && edge["kind"] == "macro_failure"
        && edge["target"] == first_fail["id"]));
    assert!(edges.iter().any(|edge| edge["source"] == reads[1]["id"]
        && edge["kind"] == "macro_failure"
        && edge["target"] == second_fail["id"]));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_reference_uncertainty_is_located_bounded_and_never_borrows_runtime_values()
-> Result<()> {
    for (value, settings, status, code) in [
        (
            "*#:",
            "[Settings]\nChannel=6115\n",
            "invalid",
            "REFERENCE_MALFORMED",
        ),
        (
            "*V:Missing-Key#",
            "[Settings]\nChannel=6115\n",
            "invalid",
            "REFERENCE_SECTION_MISSING",
        ),
        (
            "*V:Settings-#",
            "[Settings]\nChannel=6115\n",
            "invalid",
            "REFERENCE_MALFORMED",
        ),
        (
            "*V:Settings-Channel",
            "[Settings]\nChannel=6115\n",
            "invalid",
            "REFERENCE_MALFORMED",
        ),
        (
            "*V:Settings-Channel#",
            "[Settings]\nChannel=6115\nChannel=6275\n",
            "invalid",
            "REFERENCE_AMBIGUOUS",
        ),
        (
            "*V:Settings#",
            "[Settings]\nChannel=6115\nchannel=6275\n",
            "invalid",
            "REFERENCE_AMBIGUOUS",
        ),
        (
            "*V:Settings-Channel#",
            "[Settings]\nChannel=*V:Other-Channel#\n[Other]\nChannel=6115\n",
            "incomplete",
            "REFERENCE_INDIRECT_UNSUPPORTED",
        ),
        (
            "*V:Settings-*V:Macro-Param_KEY##",
            "[Settings]\nChannel=6115\n",
            "incomplete",
            "REFERENCE_NESTED_UNSUPPORTED",
        ),
        (
            "*E:Settings-Channel#",
            "[Settings]\nChannel=6115\n",
            "incomplete",
            "RUNTIME_REFERENCE_UNCHECKED",
        ),
        (
            "*I:Settings-Channel#",
            "[Settings]\nChannel=6115\n",
            "incomplete",
            "RUNTIME_REFERENCE_UNCHECKED",
        ),
        (
            "*T:Settings-Channel#",
            "[Settings]\nChannel=6115\n",
            "incomplete",
            "RUNTIME_REFERENCE_UNCHECKED",
        ),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLL|F|{value}|NULL|1|QUIT|FAIL\"\n"
        );
        let mut arguments = bundle_arguments(&text);
        arguments["runtime_bindings"] =
            serde_json::json!([{"reference":"*E:Settings-Channel#","value":"6115"}]);
        arguments["files"]
            .as_array_mut()
            .ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
            .push(serde_json::json!({"name":"SETTINGS.ini","text":settings}));
        let report = bundle_report(arguments).await?;
        assert_eq!(report["layers"]["references"], status, "{value}: {report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code
                    && issue["line"] == 4
                    && issue["field"] == "parameters")),
            "{value}: {report}"
        );
        assert_eq!(report["execution"][0]["references"], "unknown");
        assert_eq!(report["runtime_verification"], "unchecked");
        assert_eq!(report["source_files"][0]["text"], text);
    }
    let mut arguments = bundle_arguments(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLL|F|literal*text *V:Settings-Channel#|NULL|1|QUIT|FAIL\"\n",
    );
    arguments["files"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
        .push(serde_json::json!({"name":"SETTINGS.ini","text":"[Settings]\nChannel=6115\n"}));
    let report = bundle_report(arguments).await?;
    assert_eq!(report["execution"][0]["parameters"], "literal*text 6115");
    let report = bundle_report(bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "WRITE=\"Test Program|SFIS_TO_VAR|GOLDEN|NULL|1|NEXT|FAIL\"\n",
        "READ=\"DLL|F|*V:GOLDEN#|NULL|1|QUIT|FAIL\"\n",
        "[GOLDEN]\nVALUE=stale\n"
    )))
    .await?;
    assert_eq!(report["layers"]["references"], "incomplete", "{report}");
    assert_eq!(report["execution"][1]["references"], "unknown");
    for (device, function, parameters, reference) in [
        (
            "DLLGoldenKV",
            "RECORD_TESTRESULT",
            "RECORD_TIMES=1",
            "*V:DLL_GoldenKV#",
        ),
        (
            "DLLGoldenKV",
            "RECORD_TESTRESULT",
            "RECORD_TIMES=1",
            "*V:DLL_GoldenKV-RECORD_TIMES#",
        ),
        (
            "DLLGoldenKV",
            "*V:Settings-Function#",
            "RECORD_TIMES=1",
            "*V:DLL_GoldenKV#",
        ),
        (
            "*V:Settings-Device#",
            "RECORD_TESTRESULT",
            "RECORD_TIMES=1",
            "*V:DLL_GoldenKV#",
        ),
        (
            "DLLGoldenKV",
            "RECORD_TESTRESULT",
            "*V:Settings-Parameters#",
            "*V:DLL_GoldenKV#",
        ),
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nWRITE=\"{device}|{function}|{parameters}|NULL|1|NEXT|FAIL\"\nREAD=\"DLL|F|{reference}|NULL|1|QUIT|FAIL\"\n[DLL_GoldenKV]\nRECORD_TIMES=stale\n[Settings]\nFunction=RECORD_TESTRESULT\nDevice=DLLGoldenKV\nParameters=RECORD_TIMES=1\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["references"], "incomplete", "{report}");
        assert_eq!(report["execution"][1]["references"], "unknown");
        assert_ne!(report["execution"][1]["parameters"], "RECORD_TIMES=stale");
    }
    let early = "EARLY=\"DLLGoldenKV|*V:Control-Function#|RECORD_TIMES=1|NULL|1|NEXT|FAIL\"\n";
    let writer = "WRITE=\"Test Program|*V:Settings-Function#|Control|NULL|1|NEXT|FAIL\"\n";
    for rows in [format!("{early}{writer}"), format!("{writer}{early}")] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n{rows}READ=\"DLL|F|*V:DLL_GoldenKV#|NULL|1|QUIT|FAIL\"\n[Control]\nFunction=F\n[Settings]\nFunction=SFIS_TO_VAR\n[DLL_GoldenKV]\nRECORD_TIMES=stale\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["execution"][2]["references"], "unknown", "{report}");
        assert!(report["diagnostics"].as_array().is_some_and(|issues| {
            issues
                .iter()
                .any(|issue| issue["code"] == "RUNTIME_WRITER_UNCHECKED")
        }));
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_budgets_fallthrough_and_unsupported_macros_keep_honest_execution_evidence()
-> Result<()> {
    let finite = concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\nAFTER=\"AFTER\"\n[RUN#Retry:2]\n",
        "BODY#Retry:3=\"DLL|F|NULL|NULL|1|LOOP_ROW|FAIL\"\n",
        "LOOP_ROW=\"Test Program|LOOP|TEST_COUNT,5|NULL|1|BODY|NEXT\"\n",
        "[AFTER]\nDONE=\"DLL|SAVE|NULL|NULL|1|NEXT|FAIL\"\n"
    );
    let report = bundle_report(bundle_arguments(finite)).await?;
    assert_eq!(report["layers"]["control_flow"], "valid", "{report}");
    assert_eq!(report["execution"][0]["row_retry"], 3);
    assert_eq!(report["execution"][0]["item_retry"], 2);
    assert_eq!(report["execution"][1]["loop_budget"], 5);
    assert_eq!(report["execution"][2]["reachability"], "reachable");
    assert!(
        report["execution_edges"]
            .as_array()
            .is_some_and(|edges| edges.iter().any(|edge| edge["source"] == "row:1"
                && edge["target"] == "row:2"
                && edge["kind"] == "fail"))
    );
    assert!(!report["diagnostics"].to_string().contains("infinite"));
    for (header, label) in [("RUN", "A#Retry:4294967296"), ("RUN#Retry:4294967296", "A")] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[{header}]\n{label}=\"DLL|F|NULL|NULL|1|NEXT|FAIL\"\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
        assert!(report["diagnostics"].as_array().is_some_and(|issues| {
            issues
                .iter()
                .any(|issue| issue["code"] == "RETRY_BUDGET_UNSUPPORTED")
        }));
    }
    for (body, code) in [
        (
            "NESTED=\"MACRO|CHILD|NULL|NULL|1|QUIT|FAIL\"",
            "MACRO_EXPANSION_UNSUPPORTED",
        ),
        (
            "NESTED=\"MACRO|OUTER|NULL|NULL|1|QUIT|FAIL\"",
            "MACRO_RECURSION_UNSUPPORTED",
        ),
        (
            "LAST=\"DLL|F|NULL|NULL|1|NEXT|NEXT\"",
            "MACRO_FALLTHROUGH_UNSUPPORTED",
        ),
    ] {
        let mut arguments = bundle_arguments(concat!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
            "CALL=\"MACRO|OUTER|NULL|NULL|1|AFTER|FAIL\"\n",
            "AFTER=\"DLL|SAVE|NULL|NULL|1|QUIT|FAIL\"\n"
        ));
        arguments["files"].as_array_mut().ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
            .push(serde_json::json!({"name":"MACRO_LIST.ini","text":format!("[OUTER]\n{body}\n[CHILD]\nLEAF=\"DLL|CHILD_WORK|NULL|NULL|1|QUIT|FAIL\"\n")}));
        let report = bundle_report(arguments).await?;
        assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code)),
            "{report}"
        );
        assert_eq!(
            report["execution"][1]["reachability"], "unknown",
            "{report}"
        );
        if code == "MACRO_EXPANSION_UNSUPPORTED" {
            assert!(
                report["execution"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["function"] == "CHILD_WORK" && row["reachability"] == "unknown"
                    })
                }),
                "{report}"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_resolved_control_fields_and_missing_call_arguments_are_not_confused() -> Result<()>
{
    let text = concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "CALL=\"MACRO|*V:Routes-Procedure#|CHANNEL=6115|LIMIT=-35|*V:Routes-Timeout#|*V:Routes-After#|FAIL\"\n",
        "AFTER=\"DLL|SAVE|NULL|NULL|1|NEXT|FAIL\"\n",
    );
    let mut arguments = bundle_arguments(text);
    arguments["files"].as_array_mut().ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
        .extend([
            serde_json::json!({"name":"SETTINGS.ini","text":"[Routes]\nProcedure=MEASURE\nTimeout=1\nAfter=AFTER\n"}),
            serde_json::json!({"name":"MACRO_LIST.ini","text":"[MEASURE]\nREAD=\"DLL|F|*V:Macro-Param_CHANNEL#|*V:Macro-Criteria_LIMIT#|1|QUIT|FAIL\"\n"}),
        ]);
    let report = bundle_report(arguments.clone()).await?;
    assert_eq!(report["layers"]["structure"], "valid", "{report}");
    assert_eq!(report["layers"]["control_flow"], "valid", "{report}");
    assert_eq!(report["layers"]["references"], "valid", "{report}");
    for (params, status, code) in [
        ("NULL", "invalid", "MACRO_ARGUMENT_MISSING"),
        (
            "CHANNEL=6115&CHANNEL=6275",
            "invalid",
            "MACRO_ARGUMENT_AMBIGUOUS",
        ),
        (
            "unaudited-positional",
            "incomplete",
            "MACRO_ARGUMENT_CONTRACT_UNSUPPORTED",
        ),
    ] {
        let mut request = arguments.clone();
        request["files"][0]["text"] = text.replace("CHANNEL=6115", params).into();
        let report = bundle_report(request).await?;
        assert_eq!(report["layers"]["references"], status, "{params}: {report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code
                    && issue["file"] == "MACRO_LIST.ini"
                    && issue["line"] == 2
                    && issue["field"] == "parameters")),
            "{report}"
        );
    }
    let report = bundle_report(bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "SELECT=\"DLL|F|NULL|NULL|1|*E:Routes-After#|FAIL\"\n",
        "MAYBE=\"DLL|MEASURE|NULL|NULL|1|QUIT|FAIL\"\n"
    )))
    .await?;
    assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
    assert_eq!(report["status"], "invalid", "{report}");
    assert_eq!(report["execution"][1]["reachability"], "unknown");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_reference_and_graph_work_limits_are_explicit_and_request_local() -> Result<()> {
    for (token_count, value) in [
        (32, "1".to_string()),
        (1, "x".repeat(2048)),
        (40, "x".repeat(1024)),
    ] {
        let calls = (0..80)
            .map(|index| format!("CALL{index}=\"MACRO|READ|NULL|NULL|1|NEXT|FAIL\"\n"))
            .collect::<String>();
        let rows = (0..30)
            .map(|index| {
                format!(
                    "ROW{index}=\"DLL|F|{}|NULL|1|{}|FAIL\"\n",
                    "*V:Settings-Value#".repeat(token_count),
                    if index == 29 { "QUIT" } else { "NEXT" }
                )
            })
            .collect::<String>();
        let mut arguments =
            bundle_arguments(&format!("[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n{calls}"));
        arguments["files"].as_array_mut().ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
            .extend([
                serde_json::json!({"name":"MACRO_LIST.ini","text":format!("[READ]\n{rows}")}),
                serde_json::json!({"name":"SETTINGS.ini","text":format!("[Settings]\nValue={value}\n")}),
            ]);
        let report = bundle_report(arguments).await?;
        assert_eq!(report["layers"]["references"], "incomplete");
        assert!(report["diagnostics"].as_array().is_some_and(|issues| {
            issues
                .iter()
                .any(|issue| issue["code"] == "REFERENCE_LIMIT")
        }));
        assert!(
            report["execution"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["references"] == "unknown"))
        );
    }
    let rows = (0..300)
        .map(|index| format!("ROW{index}=\"DLL|F|NULL|NULL|1|*E:Routing-Next#|FAIL\"\n"))
        .collect::<String>();
    let report = bundle_report(bundle_arguments(&format!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n{rows}"
    )))
    .await?;
    assert!(
        report["execution_edges"]
            .as_array()
            .is_some_and(|edges| edges.len() <= 65_536)
    );
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "EXECUTION_EDGE_LIMIT")
    }));
    assert!(
        report["execution"]
            .as_array()
            .is_some_and(|rows| rows.iter().all(|row| row["reachability"] == "unknown"))
    );
    let rows = (0..400)
        .map(|index| format!("LOOP{index}=\"Test Program|LOOP|TEST_COUNT,5|NULL|1|QUIT|NEXT\"\n"))
        .collect::<String>();
    let report = bundle_report(bundle_arguments(&format!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n{rows}"
    )))
    .await?;
    assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "LOOP_ANALYSIS_LIMIT")
    }));
    let report = bundle_report(bundle_arguments(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLL|F|NULL|NULL|1|NEXT|FAIL\"\n",
    ))
    .await?;
    assert_eq!(report["layers"]["references"], "valid");
    assert_eq!(report["layers"]["control_flow"], "valid");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_macro_terminal_outcomes_and_exhausted_loop_paths_are_explicit() -> Result<()> {
    for terminal in ["PASS", "END", "FAIL", "QUIT"] {
        let mut arguments = bundle_arguments(concat!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
            "CALL=\"MACRO|WORK|NULL|NULL|1|SUCCESS|FAILURE\"\n",
            "SUCCESS=\"DLL|SUCCESS_WORK|NULL|NULL|1|PASS|FAIL\"\n",
            "FAILURE=\"DLL|FAILURE_WORK|NULL|NULL|1|FAIL|FAIL\"\n"
        ));
        arguments["files"].as_array_mut().ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
            .push(serde_json::json!({"name":"MACRO_LIST.ini","text":format!("[WORK]\nSTEP=\"DLL|F|NULL|NULL|1|{terminal}|{terminal}\"\n")}));
        let report = bundle_report(arguments).await?;
        assert_eq!(report["layers"]["control_flow"], "valid", "{report}");
        assert_eq!(
            report["execution"][1]["reachability"],
            if terminal == "FAIL" {
                "unreachable"
            } else {
                "reachable"
            }
        );
        assert_eq!(
            report["execution"][2]["reachability"],
            if ["PASS", "END"].contains(&terminal) {
                "unreachable"
            } else {
                "reachable"
            }
        );
    }
    for failure in ["BODY", "*V:Routes-Reenter#"] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN#Retry:2]\nBODY#Retry:3=\"DLL|F|NULL|NULL|1|LOOP_ROW|FAIL\"\nLOOP_ROW=\"Test Program|LOOP|TEST_COUNT,5|NULL|1|BODY|{failure}\"\n[Routes]\nReenter=BODY\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
        assert!(report["diagnostics"].as_array().is_some_and(|issues| {
            issues
                .iter()
                .any(|issue| issue["code"] == "LOOP_EXHAUSTION_UNCHECKED")
        }));
    }
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_auxiliary_references_and_dynamic_dispatch_remain_inspectable() -> Result<()> {
    let mut arguments = bundle_arguments(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLL|F|NULL|NULL|1|NEXT|FAIL\"\n",
    );
    arguments["files"]
        .as_array_mut()
        .ok_or_else(|| script_audit_mcp::Error::Knowledge("files missing".into()))?
        .push(
            serde_json::json!({"name":"SETTINGS.ini","text":"[Settings]\nAlias=*V:Missing-Key#\n"}),
        );
    let report = bundle_report(arguments).await?;
    assert_eq!(report["layers"]["references"], "invalid", "{report}");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| issue["code"]
                == "REFERENCE_SECTION_MISSING"
                && issue["file"] == "SETTINGS.ini"
                && issue["line"] == 2
                && issue["section"] == "Settings"
                && issue["row"] == "Alias"
                && issue["field"] == "value"))
    );
    let report = bundle_report(bundle_arguments(concat!(
        "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\n",
        "A=\"*E:Dispatch-Device#|F|NULL|NULL|1|NEXT|FAIL\"\n",
        "B=\"DLL|MEASURE|NULL|NULL|1|NEXT|FAIL\"\n"
    )))
    .await?;
    assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
    assert_eq!(report["execution"][1]["reachability"], "unknown");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_dialect_preserves_rows_and_reports_compatibility() -> Result<()> {
    let prefix = "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n";
    for (payload, expected, code) in [
        (
            "DLLQSPR#QUICK|FUNC|ANT=1|POWER=5dB|NULL|QUIT|FAIL",
            "valid",
            None,
        ),
        (
            "DLLOSP#PROXY|FUNC|NULL|NULL|0|QUIT|FAIL|ErrorCode:opaque",
            "valid",
            None,
        ),
        (
            "DLLQSPR|FUNC|NULL|NULL|100|QUIT|FAIL|ERRCODE:opaque",
            "valid",
            None,
        ),
        ("DLLQSPR|FUNC|NULL|NULL|100|QUIT|FAIL|", "valid", None),
        (
            "DLLQSPR|FUNC|NULL|NULL|1",
            "invalid",
            Some("FUNCTION_FIELD_COUNT"),
        ),
        (
            "DLLQSPR|FUNC|NULL|NULL|1|QUIT|FAIL||description",
            "invalid",
            Some("FUNCTION_EXTRA_FIELDS"),
        ),
        (
            "DLLQSPR|FUNC|NULL|NULL|-1|QUIT|FAIL",
            "invalid",
            Some("WAIT_TIME_NOT_INTEGER"),
        ),
        (
            "DLLQSPR|FUNC|NULL|NULL|1.5|QUIT|FAIL",
            "invalid",
            Some("WAIT_TIME_NOT_INTEGER"),
        ),
        (
            "DLLQSPR|FUNC|NULL|NULL|1|QUIT|FAIL|opaque",
            "invalid",
            Some("ERROR_CODE_FORMAT"),
        ),
        (
            "DLLQSPR#UNPROVEN|FUNC|NULL|NULL|1|QUIT|FAIL",
            "incomplete",
            Some("DISPATCH_SUFFIX_UNCHECKED"),
        ),
    ] {
        let text = format!("{prefix}A = \"{payload}\"\n");
        let report = bundle_report(bundle_arguments(&text)).await?;
        assert_eq!(
            report["layers"]["structure"], expected,
            "{payload}: {report}"
        );
        assert_eq!(report["source_files"][0]["text"], text);
        if let Some(code) = code {
            assert!(
                report["diagnostics"]
                    .as_array()
                    .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code)),
                "{report}"
            );
        }
        assert_ne!(report["status"], "valid");
    }
    let text = format!("{prefix}A = \"DLL|F|NULL|NULL|1|next|fail||historical\"\n");
    let mut arguments = bundle_arguments(&text);
    arguments["dialect"] = "checker_legacy".into();
    let report = bundle_report(arguments).await?;
    assert_eq!(report["status"], "invalid", "{report}");
    assert_eq!(report["layers"]["structure"], "incomplete");
    assert_eq!(report["layers"]["control_flow"], "incomplete");
    assert_eq!(
        report["script_sections"][0]["rows"][0]["segments"][8],
        "historical"
    );
    for (dialect, expected) in [("checker_legacy", "incomplete"), ("hh5k", "invalid")] {
        let mut arguments = bundle_arguments(&format!(
            "{prefix}A=\"DLL|F|NULL|NULL|1|*V:Routes-After#|FAIL\"\n[Routes]\nAfter=next\n"
        ));
        arguments["dialect"] = dialect.into();
        let report = bundle_report(arguments).await?;
        assert_eq!(report["layers"]["control_flow"], expected, "{report}");
        assert!(report["diagnostics"].as_array().is_some_and(|issues| {
            issues
                .iter()
                .any(|issue| issue["code"] == "DIALECT_TOKEN_CASE")
        }));
    }
    let report = bundle_report(bundle_arguments(&format!(
        "{prefix}A = \"DLL|F|NULL|NULL|1|QUIT|FAIL|ERRCODE:opaque\"\n"
    )))
    .await?;
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "ERROR_CODE_OPAQUE" && issue["severity"] == "warning")
    }));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_review_regression_exposes_deferred_checks_and_rejected_row_locations() -> Result<()>
{
    let text = "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|NULL|NULL|1\"\n";
    let report = bundle_report(bundle_arguments(text)).await?;
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| issue["code"]
                == "FUNCTION_FIELD_COUNT"
                && issue["file"] == "MAIN_FLOW.ini"
                && issue["line"] == 4
                && issue["section"] == "RUN"
                && issue["row"] == "A"
                && issue["field"] == "row"
                && issue["evidence"]
                    .as_str()
                    .is_some_and(|text| text.contains("fields=5"))))
    );
    let clean =
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLLQSPR|MISSING|NULL|NULL|1|QUIT|FAIL\"\n";
    let report = bundle_report(bundle_arguments(clean)).await?;
    assert_eq!(report["layers"]["control_flow"], "valid");
    assert!(report["diagnostics"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "unknown_function" && issue["severity"] == "error")
    }));
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_checks_selected_flow_local_labels_and_exact_tokens() -> Result<()> {
    let text = concat!(
        "; retained alternative\n[TEST FLOW:Normal]\nRUN = \"RUN\"\n",
        "[TEST FLOW:Sampling]\nSAMPLE = \"ABSENT\"\n[RUN]\n",
        "; INACTIVE = \"DLL|F|NULL|NULL|1|MISSING|FAIL\"\n",
        "A = \"DLL|F|NULL|NULL|1|BYPASS_END|FAIL\"\n",
        "BYPASS_END = \"DLL|F|NULL|NULL|1|NEXT|FAIL\"\n",
        "BYPASS_END = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
        "[OTHER]\nELSEWHERE = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
    );
    let report = bundle_report(bundle_arguments(text)).await?;
    assert_eq!(report["status"], "invalid", "{report}");
    assert_eq!(report["layers"]["control_flow"], "incomplete");
    assert_eq!(
        report["script_sections"][0]["rows"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    for target in ["ELSEWHERE", "INACTIVE", "MISSING_END", "next", "fail"] {
        let altered = text.replace("1|BYPASS_END|FAIL", &format!("1|{target}|FAIL"));
        let report = bundle_report(bundle_arguments(&altered)).await?;
        assert_eq!(
            report["layers"]["control_flow"], "invalid",
            "{target}: {report}"
        );
    }
    let mut sampling = bundle_arguments(text);
    sampling["selected_flow"] = "[TEST FLOW:Sampling]".into();
    assert_eq!(bundle_report(sampling).await?["status"], "invalid");
    let mut missing = bundle_arguments(text);
    missing["selected_flow"] = "[TEST FLOW:Unknown]".into();
    assert_eq!(bundle_report(missing).await?["status"], "invalid");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_detects_ambiguous_sections_and_missing_macros() -> Result<()> {
    let mut auxiliary = bundle_arguments(
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
    );
    auxiliary["files"].as_array_mut().ok_or_else(||
        script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"SETTINGS.ini","text":"[Settings]\nPassword = \"sanitized-secret\n"}));
    let report = bundle_report(auxiliary).await?;
    assert_eq!(report["layers"]["structure"], "invalid");
    assert!(
        report["diagnostics"]
            .as_array()
            .is_some_and(|issues| issues
                .iter()
                .any(|issue| issue["code"] == "UNTERMINATED_QUOTE"
                    && issue["file"] == "SETTINGS.ini"
                    && issue["line"] == 2
                    && issue["section"] == "Settings"
                    && issue["row"] == "Password"))
    );
    for text in [
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n[run#Retry:2]\nB = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = DLL|F|NULL|NULL|1|QUIT|FAIL\n",
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|bad\"quote|NULL|1|QUIT|FAIL\"\n",
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n",
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n; no executable implementation\n",
    ] {
        let report = bundle_report(bundle_arguments(text)).await?;
        assert_eq!(report["status"], "invalid", "{report}");
    }
    let text =
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"MACRO|MISSING|NULL|NULL|1|QUIT|FAIL\"\n";
    let report = bundle_report(bundle_arguments(text)).await?;
    assert_eq!(report["layers"]["control_flow"], "incomplete", "{report}");
    let mut arguments = bundle_arguments(text);
    arguments["files"].as_array_mut().ok_or_else(||
        script_audit_mcp::Error::Knowledge("fixture files missing".into()))?
        .push(serde_json::json!({"name":"MACRO_LIST.ini","text":"[OTHER]\nA = \"MACRO|ALSO_MISSING|NULL|NULL|1|PASS|FAIL\"\n"}));
    let report = bundle_report(arguments).await?;
    assert_eq!(report["layers"]["control_flow"], "invalid", "{report}");
    assert_eq!(
        report["diagnostics"].as_array().map(|issues| issues
            .iter()
            .filter(|issue| issue["code"] == "MACRO_TARGET_MISSING")
            .count()),
        Some(2)
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_redacts_diagnostics_and_never_resolves_ambient_inputs() -> Result<()> {
    let text = concat!(
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n",
        "A = \"DLL|F|*V:/not/supplied.ini-Key#|NULL|1|station-secret|FAIL\"\n",
        "B = \"DLL|F|URL=https://operator:url-secret@example.invalid/config|NULL|1|url-secret|FAIL\"\n",
        "C = \"DLL|F|*E:Label-ISN#|NULL|1|binding-secret|FAIL\"\n",
        "[Settings]\nPASSWORD = \"station-secret\"\n",
    );
    let mut arguments = bundle_arguments(text);
    arguments["runtime_bindings"] = serde_json::json!([
        {"reference":"*E:Label-ISN#","value":"binding-secret"}
    ]);
    let report = bundle_report(arguments).await?;
    let diagnostics = report["diagnostics"].to_string();
    for secret in ["station-secret", "url-secret", "binding-secret"] {
        assert!(!diagnostics.contains(secret), "{diagnostics}");
        assert!(!report["execution"].to_string().contains(secret));
    }
    assert_eq!(report["source_files"][0]["text"], text);
    assert_eq!(report["layers"]["references"], "invalid");
    assert_eq!(report["runtime_verification"], "unchecked");
    assert!(diagnostics.contains("[REDACTED]"));
    for payload in [
        "PASSWORD=*V:Settings-Key#",
        "*V:Settings-Key#",
        "*V:Settings#",
    ] {
        let text = format!(
            "[TEST FLOW:Normal]\nRUN=\"RUN\"\n[RUN]\nA=\"DLL|F|{payload}|NULL|1|*V:Settings-Key#|FAIL\"\n[Settings]\nKey=resolved-secret\nPASSWORD=*V:Settings-Key#\n"
        );
        let report = bundle_report(bundle_arguments(&text)).await?;
        for field in ["diagnostics", "execution"] {
            assert!(
                !report[field].to_string().contains("resolved-secret"),
                "{field}: {}",
                report[field]
            );
        }
        assert_eq!(report["source_files"][0]["text"], text);
        assert_eq!(report["execution"][0]["redacted"], true);
    }
    let clean = "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n";
    assert_eq!(
        bundle_report(bundle_arguments(clean)).await?["layers"]["structure"],
        "valid"
    );
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_returns_structured_errors_for_unanalyzable_requests() -> Result<()> {
    let base = bundle_arguments("[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n");
    let mut requests = Vec::new();
    for files in [
        serde_json::json!([]),
        serde_json::json!([
            {"name":"MAIN_FLOW.ini","text":""}, {"name":"main_flow.INI","text":""}
        ]),
        serde_json::json!([{"name":"https://example.invalid/file.ini","text":""}]),
        serde_json::json!([{"name":"SETTINGS.ini","text":""}]),
    ] {
        let mut request = base.clone();
        request["files"] = files;
        requests.push(request);
    }
    let mut too_large = base.clone();
    too_large["files"][0]["text"] = "x"
        .repeat(script_audit_mcp::bundle::MAX_TEXT_BYTES + 1)
        .into();
    requests.push(too_large);
    let mut too_many = base.clone();
    too_many["files"][0]["text"] = "x\n"
        .repeat(script_audit_mcp::bundle::MAX_RECORDS + 1)
        .into();
    requests.push(too_many);
    let mut blank = base.clone();
    blank["selected_flow"] = "".into();
    requests.push(blank);
    let mut not_a_flow = base.clone();
    not_a_flow["selected_flow"] = "RUN".into();
    requests.push(not_a_flow);
    let mut malformed_binding = base.clone();
    malformed_binding["runtime_bindings"] =
        serde_json::json!([{"reference":"https://example.invalid","value":null}]);
    requests.push(malformed_binding);
    let mut long_line = base.clone();
    long_line["files"][0]["text"] = "x".repeat(8193).into();
    requests.push(long_line);
    let mut large_total = base.clone();
    large_total["files"][0]["text"] = format!("{}\n", "x".repeat(8192)).repeat(129).into();
    requests.push(large_total);
    let mut too_many_files = base.clone();
    too_many_files["files"] = (0..17)
        .map(|index| serde_json::json!({"name":format!("file{index}.ini"),"text":""}))
        .collect();
    requests.push(too_many_files);
    let mut too_many_bindings = base.clone();
    too_many_bindings["runtime_bindings"] =
        vec![serde_json::json!({"reference":"*E:Label-ISN#","value":null}); 129].into();
    requests.push(too_many_bindings);
    let mut expansion = base.clone();
    expansion["files"][0]["text"] = format!(
        "[TEST FLOW:Normal]\n{}[RUN]\n{}",
        "RUN = \"RUN\"\n".repeat(200),
        "A = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n".repeat(100)
    )
    .into();
    requests.push(expansion);
    for arguments in requests {
        let result = call_bundle(arguments).await?;
        assert_eq!(result.is_error, Some(true));
        assert!(
            result
                .structured_content
                .is_some_and(|value| value["error"]["code"] == "invalid_input")
        );
    }
    assert_eq!(bundle_report(base).await?["status"], "invalid");
    let items = (0..200)
        .map(|index| format!("ITEM{index} = \"ITEM{index}\"\n"))
        .collect::<String>();
    let sections = (0..200)
        .map(|index| format!("[ITEM{index}]\nA = \"DLL|F|NULL|NULL|1|QUIT|FAIL\"\n"))
        .collect::<String>();
    let many_sections = format!("[TEST FLOW:Normal]\n{items}{sections}");
    let report = bundle_report(bundle_arguments(&many_sections)).await?;
    assert_eq!(report["layers"]["structure"], "valid");
    assert_eq!(report["layers"]["control_flow"], "valid");
    Ok(())
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn bundle_uses_one_snapshot_and_keeps_concurrent_requests_isolated() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct CountingCatalog(Arc<AtomicUsize>);
    impl script_audit_mcp::Catalog for CountingCatalog {
        fn snapshot(&self) -> Result<Snapshot> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(fixture_snapshot())
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let server =
        script_audit_mcp::mcp::McpServer::new(Arc::new(CountingCatalog(Arc::clone(&count))));
    let invalid =
        serde_json::from_value(bundle_arguments("[TEST FLOW:Normal]\nRUN = \"MISSING\"\n"))
            .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let clean = serde_json::from_value(bundle_arguments(
        "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\nA = \"DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|1|QUIT|FAIL\"\n",
    ))
    .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let (bad, good) = tokio::join!(
        server.validate_ini_bundle(rmcp::handler::server::wrapper::Parameters(invalid)),
        server.validate_ini_bundle(rmcp::handler::server::wrapper::Parameters(clean)),
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let bad = bad.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    let good = good.map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?;
    assert!(
        bad.structured_content
            .is_some_and(|report| report["status"] == "invalid")
    );
    assert!(good.structured_content.is_some_and(
        |report| report["status"] == "valid" && report["layers"]["control_flow"] == "valid"
    ));
    Ok(())
}

#[test]
fn review_regression_known_errors_outrank_unresolved_schema() -> Result<()> {
    let mut snapshot = fixture_snapshot();
    snapshot
        .parameter_links
        .push(snapshot.parameter_links[0].clone());
    let engine = Engine::new(snapshot);
    for (timeout, pass, fail, expected) in [
        ("20000", "NEXT", "FAIL", ValidationStatus::Incomplete),
        ("0", "NEXT", "FAIL", ValidationStatus::Invalid),
        ("invalid", "NEXT", "FAIL", ValidationStatus::Invalid),
        ("20000", "", "FAIL", ValidationStatus::Invalid),
    ] {
        let line =
            format!("DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|{timeout}|{pass}|{fail}|");
        assert_eq!(engine.validate_line(&line, None)?.status, expected);
    }
    for parameters in ["ANT=15&ANT=2", "ANT", "ANT="] {
        let line = format!("DLLWIFI_TEST|TX_MULTI_VERIFICATION|{parameters}|NULL|20000|NEXT|FAIL|");
        assert_eq!(
            engine.validate_line(&line, None)?.status,
            ValidationStatus::Invalid
        );
    }
    Ok(())
}

#[cfg(feature = "legacy-sqlite")]
mod database {
    use super::*;
    use rusqlite::{Connection, params};
    use script_audit_mcp::{Catalog, sqlite::SqliteCatalog};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct FixtureDatabase {
        directory: PathBuf,
        catalog: SqliteCatalog,
    }

    impl FixtureDatabase {
        fn new() -> Result<Self> {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| script_audit_mcp::Error::Knowledge(error.to_string()))?
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "script-audit-mcp-fixture-{}-{stamp}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory)?;
            let path = directory.join("fixture.db");
            let connection = Connection::open(&path)?;
            connection.execute_batch(include_str!("fixtures/schema.sql"))?;
            let snapshot = fixture_snapshot();
            for function in snapshot.functions {
                connection.execute("INSERT INTO functions (source, interface, name, description, convention, category, execution_role, execution_phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![function.source, function.interface, function.name, function.description, function.convention, function.category, function.execution_role, function.execution_phase])?;
            }
            for (table, definitions) in [
                ("parameter_definitions", snapshot.parameter_definitions),
                ("criteria_definitions", snapshot.criteria_definitions),
            ] {
                for definition in definitions {
                    connection.execute(&format!("INSERT INTO {table} (name, device_name, description, type, unit, default_value, allowed_values, cardinality, value_pattern, required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                        params![definition.name, definition.device_name, definition.description, definition.kind, definition.unit, definition.default_value, definition.allowed_values, definition.cardinality, definition.value_pattern, definition.required])?;
                }
            }
            for (table, links) in [
                ("parameter_links", snapshot.parameter_links),
                ("criteria_links", snapshot.criteria_links),
            ] {
                for link in links {
                    connection.execute(&format!("INSERT INTO {table} (function_source, function_name, device_name, name, position, required) VALUES (?, ?, ?, ?, ?, ?)"),
                        params![link.function_source, link.function_name, link.device_name, link.name, link.position, link.required])?;
                }
            }
            for example in snapshot.examples {
                connection.execute("INSERT INTO examples (function_source, device_name, function_name, script, meaning) VALUES (?, ?, ?, ?, ?)",
                    params![example.function_source, example.device_name, example.function_name, example.script, example.meaning])?;
            }
            drop(connection);
            Ok(Self {
                directory,
                catalog: SqliteCatalog::new(path)?,
            })
        }

        fn engine(&self) -> Result<Engine> {
            Ok(Engine::new(self.catalog.snapshot()?))
        }
    }

    impl Drop for FixtureDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn db_list_functions_reads_catalog() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        assert_eq!(fixture.engine()?.list_functions(Some("SSH"))?.len(), 1);
        Ok(())
    }

    #[test]
    fn db_get_function_reads_full_schema_and_examples() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        let schema =
            fixture
                .engine()?
                .get_function("DLLWIFI_TEST", "TX_MULTI_VERIFICATION", None)?;
        assert_eq!(schema.parameters.len(), 1);
        assert_eq!(schema.examples.len(), 1);
        assert!(schema.function.composition_supported);
        Ok(())
    }

    #[test]
    fn db_suggest_criteria_reads_known_patterns() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        assert_eq!(
            fixture
                .engine()?
                .suggest_criteria("DLLWIFI_TEST", "TX_MULTI_VERIFICATION", None)?
                .criteria[0]
                .name,
            "POWER"
        );
        Ok(())
    }

    #[test]
    fn db_compose_line_emits_validated_line() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        assert_eq!(
            fixture.engine()?.compose_line(wifi_request())?.line,
            "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|POWER=5dB|20000|NEXT|FAIL|"
        );
        Ok(())
    }

    #[test]
    fn db_validate_line_checks_every_known_field() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        assert_eq!(
            fixture
                .engine()?
                .validate_line(
                    "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=15,2|NULL|20000|NEXT|FAIL|",
                    None
                )?
                .status,
            ValidationStatus::Valid
        );
        assert_eq!(
            fixture
                .engine()?
                .validate_line(
                    "DLLWIFI_TEST|TX_MULTI_VERIFICATION|ANT=999|NULL|20000|NEXT|FAIL|",
                    None
                )?
                .status,
            ValidationStatus::Invalid
        );
        Ok(())
    }

    #[test]
    fn db_catalog_reads_without_changing_file_or_creating_missing_database() -> Result<()> {
        let fixture = FixtureDatabase::new()?;
        let before = fs::read(fixture.catalog.path())?;
        fixture.engine()?.compose_line(wifi_request())?;
        assert_eq!(fs::read(fixture.catalog.path())?, before);
        let missing = fixture.directory.join("missing.db");
        assert!(SqliteCatalog::new(&missing).is_err());
        assert!(!missing.exists());
        Ok(())
    }
}
