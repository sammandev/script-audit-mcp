use std::{env, sync::Arc};

use rmcp::{ServiceExt, transport::stdio};
use script_audit_mcp::{Catalog, Error, Result, mcp::McpServer, postgres::PostgresCatalog};

fn database_argument() -> Result<Option<String>> {
    if let Some(argument) = env::args_os().nth(1) {
        if argument == "--help" || argument == "-h" {
            eprintln!(
                "script-audit-mcp\nSet SCRIPT_AUDIT_DATABASE_URL or DATABASE_URL to a PostgreSQL URL. Catalog transactions are read-only; transport is stdio."
            );
            return Ok(None);
        }
        return Err(Error::InvalidInput {
            field: "arguments".into(),
            message: "only --help is accepted; supply credentials through the environment".into(),
        });
    }
    env::var("SCRIPT_AUDIT_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .ok()
        .filter(|database| !database.is_empty())
        .map(Some)
        .ok_or_else(|| Error::InvalidInput {
            field: "SCRIPT_AUDIT_DATABASE_URL".into(),
            message: "set SCRIPT_AUDIT_DATABASE_URL or DATABASE_URL; no database is created automatically".into(),
        })
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let Some(database) = database_argument()? else {
        return Ok(());
    };
    let catalog = PostgresCatalog::new(&database)?;
    let probe = catalog.clone();
    tokio::task::spawn_blocking(move || probe.snapshot()).await??;
    let service = McpServer::new(Arc::new(catalog)).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
