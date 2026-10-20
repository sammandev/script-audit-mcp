use std::{env, sync::Arc};

use rmcp::{ServiceExt, transport::stdio};
use script_audit_mcp::{Catalog, Error, Result, mcp::McpServer, postgres::PostgresCatalog};

const HTTP_HOST_DEFAULT: &str = "127.0.0.1";
const HTTP_PORT_DEFAULT: u16 = 8080;

#[derive(Debug)]
struct HttpOptions {
    host: String,
    port: u16,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            host: HTTP_HOST_DEFAULT.to_string(),
            port: HTTP_PORT_DEFAULT,
        }
    }
}

fn missing_value(argument: &str) -> Error {
    Error::InvalidInput {
        field: "arguments".into(),
        message: format!("{argument} requires a value"),
    }
}

fn arguments() -> Result<(Option<String>, Option<HttpOptions>)> {
    let mut http: Option<HttpOptions> = None;
    let mut args = env::args_os();
    let _program = args.next();
    while let Some(argument) = args.next() {
        let argument = argument.to_string_lossy().into_owned();
        match argument.as_str() {
            "--help" | "-h" => {
                eprintln!(
                    "script-audit-mcp\nSet SCRIPT_AUDIT_DATABASE_URL or DATABASE_URL to a PostgreSQL URL.\nDefault transport is stdio. --http serves the MCP Streamable HTTP transport (--host <address>, --port <number>). Catalog transactions are read-only."
                );
                return Ok((None, None));
            }
            "--http" => {
                http.get_or_insert_with(HttpOptions::default);
            }
            "--host" => {
                let value = args.next().ok_or_else(|| missing_value("--host"))?;
                let options = http.get_or_insert_with(HttpOptions::default);
                options.host = value.to_string_lossy().into_owned();
                if options.host.is_empty() {
                    return Err(Error::InvalidInput {
                        field: "arguments".into(),
                        message: "--host requires a nonempty address".into(),
                    });
                }
            }
            "--port" => {
                let value = args.next().ok_or_else(|| missing_value("--port"))?;
                let port =
                    value
                        .to_string_lossy()
                        .parse::<u16>()
                        .map_err(|_| Error::InvalidInput {
                            field: "arguments".into(),
                            message: "--port requires a number between 0 and 65535".into(),
                        })?;
                http.get_or_insert_with(HttpOptions::default).port = port;
            }
            other => {
                return Err(Error::InvalidInput {
                    field: "arguments".into(),
                    message: format!(
                        "unknown argument {other}; accepted: --help, --http, --host <address>, --port <number>"
                    ),
                });
            }
        }
    }
    let database = env::var("SCRIPT_AUDIT_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .ok()
        .filter(|database| !database.is_empty());
    Ok((database, http))
}

#[cfg(feature = "http")]
async fn serve_http(
    catalog: Arc<PostgresCatalog>,
    options: HttpOptions,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let http_service = StreamableHttpService::new(
        move || Ok(McpServer::new(catalog.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", http_service);
    let listener = tokio::net::TcpListener::bind((options.host.as_str(), options.port)).await?;
    eprintln!(
        "script-audit-mcp: streamable HTTP listening on http://{}:{}/mcp",
        options.host, options.port
    );
    axum::serve(listener, router).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (database, http) = arguments()?;
    let Some(database) = database else {
        return Ok(());
    };
    let catalog = PostgresCatalog::new(&database)?;
    let probe = catalog.clone();
    tokio::task::spawn_blocking(move || probe.snapshot()).await??;
    let catalog = Arc::new(catalog);
    #[cfg(feature = "http")]
    if let Some(options) = http {
        return serve_http(catalog, options).await;
    }
    #[cfg(not(feature = "http"))]
    let _ = http;
    let service = McpServer::new(catalog).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
