use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, Row, TransactionBehavior};

use crate::{
    Catalog, Error, Result,
    model::{Definition, Example, Function, Link, Snapshot},
};

#[derive(Clone, Debug)]
pub struct SqliteCatalog {
    path: PathBuf,
}

impl SqliteCatalog {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        if !path.is_file() {
            return Err(Error::InvalidInput {
                field: "db".into(),
                message: "database path must be an existing file".into(),
            });
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Catalog for SqliteCatalog {
    fn snapshot(&self) -> Result<Snapshot> {
        let mut connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(2))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let functions = rows(
            &transaction,
            "SELECT source, interface, name, description, convention, category, execution_role, execution_phase FROM functions ORDER BY source, interface, name",
            |row| {
                Ok(Function {
                    source: row.get("source")?,
                    interface: row.get("interface")?,
                    name: row.get("name")?,
                    description: row.get("description")?,
                    convention: row.get("convention")?,
                    category: row.get("category")?,
                    execution_role: row.get("execution_role")?,
                    execution_phase: row.get("execution_phase")?,
                    composition_supported: false,
                })
            },
        )?;
        let parameter_definitions = definitions(&transaction, "parameter_definitions")?;
        let criteria_definitions = definitions(&transaction, "criteria_definitions")?;
        let parameter_links = links(&transaction, "parameter_links")?;
        let criteria_links = links(&transaction, "criteria_links")?;
        let examples = rows(
            &transaction,
            "SELECT function_source, device_name, function_name, script, meaning FROM examples ORDER BY id",
            |row| {
                Ok(Example {
                    function_source: row.get("function_source")?,
                    device_name: row.get("device_name")?,
                    function_name: row.get("function_name")?,
                    script: row.get("script")?,
                    meaning: row.get("meaning")?,
                })
            },
        )?;
        transaction.commit()?;
        Ok(Snapshot {
            functions,
            parameter_definitions,
            criteria_definitions,
            parameter_links,
            criteria_links,
            examples,
        })
    }
}

fn rows<Output>(
    connection: &Connection,
    sql: &str,
    map: impl FnMut(&Row<'_>) -> rusqlite::Result<Output>,
) -> Result<Vec<Output>> {
    let mut statement = connection.prepare(sql)?;
    let values = statement
        .query_map([], map)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(values)
}

fn definitions(connection: &Connection, table: &str) -> Result<Vec<Definition>> {
    rows(
        connection,
        &format!(
            "SELECT name, device_name, description, type, unit, default_value, allowed_values, cardinality, value_pattern, required FROM {table} ORDER BY name, device_name"
        ),
        |row| {
            Ok(Definition {
                name: row.get("name")?,
                device_name: row.get("device_name")?,
                description: row.get("description")?,
                kind: row.get("type")?,
                unit: row.get("unit")?,
                default_value: row.get("default_value")?,
                allowed_values: row.get("allowed_values")?,
                cardinality: row.get("cardinality")?,
                value_pattern: row.get("value_pattern")?,
                required: row.get::<_, i64>("required")? != 0,
            })
        },
    )
}

fn links(connection: &Connection, table: &str) -> Result<Vec<Link>> {
    rows(
        connection,
        &format!(
            "SELECT name, function_source, function_name, device_name, position, required FROM {table} ORDER BY id"
        ),
        |row| {
            Ok(Link {
                name: row.get("name")?,
                function_source: row.get("function_source")?,
                function_name: row.get("function_name")?,
                device_name: row.get("device_name")?,
                position: row.get("position")?,
                required: row.get::<_, i64>("required")? != 0,
            })
        },
    )
}
