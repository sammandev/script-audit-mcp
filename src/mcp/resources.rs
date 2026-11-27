//! Read-only `catalog://` resources. Each read calls the matching tool, so a resource and its
//! tool always return the same JSON.

use rmcp::{
    ErrorData,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ReadResourceResult, Resource, ResourceContents, ResourceTemplate},
};

use super::{
    DefinitionRequest, GetDeviceRequest, GetFunctionRequest, ListFunctionsRequest, McpServer,
};
use crate::discovery::{ExampleQuery, FieldKind};

const JSON: &str = "application/json";
const MARKDOWN: &str = "text/markdown";
const SCHEME: &str = "catalog://";

/// Static reference documents, compiled in from `resources/docs` so they version with the code.
const DOCS: [(&str, &str, &str, &str, &str); 3] = [
    (
        "docs://script-grammar",
        "script-grammar",
        "Script Line Grammar",
        "Line fields, conventions 1 and 2, Named and Raw profiles, SINGLE and MULTIPLE values, NULL criteria, and *V:/*E:/*I:/*T: references.",
        include_str!("../../resources/docs/script-grammar.md"),
    ),
    (
        "docs://script-devices",
        "script-devices",
        "Script Devices",
        "Script device versus Device scope and Interface, DLL prefixes, #QUICK and #PROXY mode suffixes, and Interface aliases.",
        include_str!("../../resources/docs/script-devices.md"),
    ),
    (
        "docs://ini-bundle-dialects",
        "ini-bundle-dialects",
        "INI Bundle Dialects",
        "INI bundle files and the hh5k and checker_legacy dialect rules used by the bundle tools.",
        include_str!("../../resources/docs/ini-bundle-dialects.md"),
    ),
];

pub(super) fn list() -> Vec<Resource> {
    let docs = DOCS.iter().map(|(uri, name, title, description, text)| {
        Resource::new(*uri, *name)
            .with_title(*title)
            .with_description(*description)
            .with_mime_type(MARKDOWN)
            .with_size(text.len() as u64)
    });
    [
        Resource::new("catalog://devices", "devices")
            .with_title("Script Devices")
            .with_description("Every Script device with its source, Interface, DLL modes, and Function counts; the list_devices result.")
            .with_mime_type(JSON),
        Resource::new("catalog://info", "catalog-info")
            .with_title("Catalog Info")
            .with_description("Catalog contract, sha256 content-hash revision, server version, and row counts; the catalog_info result.")
            .with_mime_type(JSON),
    ]
    .into_iter()
    .chain(docs)
    .collect()
}

pub(super) fn templates() -> Vec<ResourceTemplate> {
    [
        (
            "catalog://devices/{device}",
            "device",
            "Script Device",
            "One Script device's summary, readiness counts, and linked fields; the get_device result. An Interface name is accepted as an alias.",
        ),
        (
            "catalog://devices/{device}/functions",
            "device-functions",
            "Script Device Functions",
            "Every Function on a Script device with readiness; the list_functions result filtered by device.",
        ),
        (
            "catalog://functions/{device}/{name}",
            "function",
            "Function",
            "One Function's parameters, criteria, and Examples; the get_function result.",
        ),
        (
            "catalog://definitions/{kind}/{name}",
            "definition",
            "Field Definition",
            "Global and scoped definitions of a parameter or criterion (kind is `parameter` or `criterion`); the get_definition result.",
        ),
        (
            "catalog://examples/{device}/{name}",
            "function-examples",
            "Function Examples",
            "Stored Examples for one Function (first page); the list_examples result.",
        ),
    ]
    .into_iter()
    .map(|(uri_template, name, title, description)| {
        ResourceTemplate::new(uri_template, name)
            .with_title(title)
            .with_description(description)
            .with_mime_type(JSON)
    })
    .collect()
}

enum Route {
    Devices,
    Info,
    Device(String),
    DeviceFunctions(String),
    Function(String, String),
    Definition(FieldKind, String),
    Examples(String, String),
}

fn route(uri: &str) -> Option<Route> {
    let segments = uri
        .strip_prefix(SCHEME)?
        .split('/')
        .map(percent_decode)
        .collect::<Option<Vec<_>>>()?;
    if segments.iter().any(String::is_empty) {
        return None;
    }
    let mut segments = segments.into_iter();
    let route = match (segments.next()?.as_str(), segments.next(), segments.next()) {
        ("devices", None, None) => Route::Devices,
        ("info", None, None) => Route::Info,
        ("devices", Some(device), None) => Route::Device(device),
        ("devices", Some(device), Some(rest)) if rest == "functions" => {
            Route::DeviceFunctions(device)
        }
        ("functions", Some(device), Some(name)) => Route::Function(device, name),
        ("definitions", Some(kind), Some(name)) => {
            Route::Definition(serde_json::from_value(kind.into()).ok()?, name)
        }
        ("examples", Some(device), Some(name)) => Route::Examples(device, name),
        _ => return None,
    };
    segments.next().is_none().then_some(route)
}

/// Decodes `%XX` escapes; `None` for a malformed escape or non-UTF-8 result.
fn percent_decode(segment: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(segment.len());
    let mut rest = segment.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let hex = tail.get(..2)?;
            bytes.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            rest = tail.get(2..)?;
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

pub(super) async fn read(server: &McpServer, uri: &str) -> Result<ReadResourceResult, ErrorData> {
    let not_found = |data: Option<serde_json::Value>| {
        ErrorData::resource_not_found(format!("unknown resource: {uri}"), data)
    };
    if let Some((_, _, _, _, text)) = DOCS.iter().find(|doc| doc.0 == uri) {
        return Ok(ReadResourceResult::new(vec![
            ResourceContents::text(*text, uri).with_mime_type(MARKDOWN),
        ]));
    }
    let Some(route) = route(uri) else {
        return Err(not_found(Some(serde_json::json!({ "uri": uri }))));
    };
    let unknown_definition = matches!(route, Route::Definition(..));
    let result = match route {
        Route::Devices => server.list_devices().await?,
        Route::Info => server.catalog_info().await?,
        Route::Device(device) => {
            server
                .get_device(Parameters(GetDeviceRequest { device }))
                .await?
        }
        Route::DeviceFunctions(device) => {
            server
                .list_functions(Parameters(ListFunctionsRequest {
                    device: Some(device),
                    ..ListFunctionsRequest::default()
                }))
                .await?
        }
        Route::Function(device, name) => {
            server
                .get_function(Parameters(GetFunctionRequest {
                    device,
                    name,
                    device_scope: None,
                }))
                .await?
        }
        Route::Definition(kind, name) => {
            server
                .get_definition(Parameters(DefinitionRequest {
                    kind,
                    name,
                    device_scope: None,
                }))
                .await?
        }
        Route::Examples(device, name) => {
            server
                .list_examples(Parameters(ExampleQuery {
                    device: Some(device),
                    function: Some(name),
                    ..ExampleQuery::default()
                }))
                .await?
        }
    };
    let body = structured(result, &not_found)?;
    // get_definition answers an unknown name with an empty list; as a resource it does not exist.
    if unknown_definition
        && body["definitions"]
            .as_array()
            .is_none_or(|definitions| definitions.is_empty())
    {
        return Err(not_found(Some(serde_json::json!({ "uri": uri }))));
    }
    let text = serde_json::to_string(&body)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type(JSON),
    ]))
}

/// Unwraps a tool result, turning its `isError` envelope into the matching JSON-RPC error.
fn structured(
    result: CallToolResult,
    not_found: &dyn Fn(Option<serde_json::Value>) -> ErrorData,
) -> Result<serde_json::Value, ErrorData> {
    let body = result
        .structured_content
        .ok_or_else(|| ErrorData::internal_error("tool returned no structured content", None))?;
    if result.is_error != Some(true) {
        return Ok(body);
    }
    let error = body["error"].clone();
    let message = error["message"].as_str().unwrap_or_default().to_string();
    Err(match error["code"].as_str().unwrap_or_default() {
        "unknown_device" | "unknown_function" | "invalid_input" => not_found(Some(error)),
        "knowledge_error" | "file_error" | "database_error" => {
            ErrorData::internal_error(message, Some(error))
        }
        _ => ErrorData::invalid_params(message, Some(error)),
    })
}
