use std::{env, fs, time::Duration};

use native_tls::{Certificate, Protocol, TlsConnector};
use postgres::{Client, Config, IsolationLevel, NoTls, Row, Transaction, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use url::Url;

use crate::{
    Catalog, Error, Result,
    model::{Definition, Example, Function, Link, Snapshot},
};

#[derive(Clone)]
pub struct PostgresCatalog {
    config: Config,
    tls: Option<TlsConnector>,
}

impl PostgresCatalog {
    pub fn new(dsn: &str) -> Result<Self> {
        let invalid = || Error::InvalidInput {
            field: "DATABASE_URL".into(),
            message: "expected a PostgreSQL URL with sslmode=verify-full, require, or disable"
                .into(),
        };
        let mut connection_url = Url::parse(dsn).map_err(|_| invalid())?;
        if !matches!(connection_url.scheme(), "postgres" | "postgresql") {
            return Err(invalid());
        }
        let mut mode = "verify-full".to_string();
        let mut root = env::var("PGSSLROOTCERT").ok();
        let mut options = Vec::new();
        for (key, value) in connection_url.query_pairs() {
            match key.as_ref() {
                "sslmode" => mode = value.into_owned(),
                "sslrootcert" => root = Some(value.into_owned()),
                _ => options.push((key.into_owned(), value.into_owned())),
            }
        }
        if !matches!(mode.as_str(), "verify-full" | "require" | "disable") {
            return Err(invalid());
        }
        connection_url
            .query_pairs_mut()
            .clear()
            .extend_pairs(options);
        let mut config: Config = connection_url.as_str().parse().map_err(|_| invalid())?;
        if config.get_password().is_none()
            && let Ok(password) = env::var("PGPASSWORD")
        {
            config.password(password);
        }
        config
            .application_name("script-audit-mcp")
            .connect_timeout(Duration::from_secs(10));
        let tls = if mode == "disable" {
            config.ssl_mode(SslMode::Disable);
            None
        } else {
            config.ssl_mode(SslMode::Require);
            let mut builder = TlsConnector::builder();
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            if let Some(path) = root.filter(|path| !path.is_empty()) {
                let certificate = Certificate::from_pem(&fs::read(path)?)
                    .map_err(|error| Error::Knowledge(error.to_string()))?;
                builder.add_root_certificate(certificate);
            }
            Some(
                builder
                    .build()
                    .map_err(|error| Error::Knowledge(error.to_string()))?,
            )
        };
        Ok(Self { config, tls })
    }

    fn connect(&self) -> Result<Client> {
        match &self.tls {
            Some(tls) => Ok(self.config.connect(MakeTlsConnector::new(tls.clone()))?),
            None => Ok(self.config.connect(NoTls)?),
        }
    }
}

impl Catalog for PostgresCatalog {
    fn snapshot(&self) -> Result<Snapshot> {
        let mut connection = self.connect()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        transaction.batch_execute("SET LOCAL statement_timeout = '15s'")?;
        let functions = rows(
            &mut transaction,
            "SELECT source, interface, name, description, convention, category, execution_role, execution_phase FROM functions ORDER BY source, interface, name",
            |row| {
                Ok(Function {
                    source: row.try_get("source")?,
                    interface: row.try_get("interface")?,
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                    convention: row.try_get("convention")?,
                    category: row.try_get("category")?,
                    execution_role: row.try_get("execution_role")?,
                    execution_phase: row.try_get("execution_phase")?,
                    composition_supported: false,
                })
            },
        )?;
        let parameter_definitions = definitions(&mut transaction, "parameter_definitions")?;
        let criteria_definitions = definitions(&mut transaction, "criteria_definitions")?;
        let parameter_links = links(&mut transaction, "parameter_links")?;
        let criteria_links = links(&mut transaction, "criteria_links")?;
        let examples = rows(
            &mut transaction,
            "SELECT function_source, device_name, function_name, script, meaning FROM examples ORDER BY id",
            |row| {
                Ok(Example {
                    function_source: row.try_get("function_source")?,
                    device_name: row.try_get("device_name")?,
                    function_name: row.try_get("function_name")?,
                    script: row.try_get("script")?,
                    meaning: row.try_get("meaning")?,
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
    transaction: &mut Transaction<'_>,
    sql: &str,
    map: impl FnMut(&Row) -> Result<Output>,
) -> Result<Vec<Output>> {
    transaction.query(sql, &[])?.iter().map(map).collect()
}

fn definitions(transaction: &mut Transaction<'_>, table: &str) -> Result<Vec<Definition>> {
    rows(
        transaction,
        &format!(
            "SELECT name, device_name, description, type, unit, default_value, allowed_values, cardinality, value_pattern, required FROM {table} ORDER BY name, device_name"
        ),
        |row| {
            Ok(Definition {
                name: row.try_get("name")?,
                device_name: row.try_get("device_name")?,
                description: row.try_get("description")?,
                kind: row.try_get("type")?,
                unit: row.try_get("unit")?,
                default_value: row.try_get("default_value")?,
                allowed_values: row.try_get("allowed_values")?,
                cardinality: row.try_get("cardinality")?,
                value_pattern: row.try_get("value_pattern")?,
                required: row.try_get::<_, i64>("required")? != 0,
            })
        },
    )
}

fn links(transaction: &mut Transaction<'_>, table: &str) -> Result<Vec<Link>> {
    rows(
        transaction,
        &format!(
            "SELECT name, function_source, function_name, device_name, position, required FROM {table} ORDER BY id"
        ),
        |row| {
            Ok(Link {
                name: row.try_get("name")?,
                function_source: row.try_get("function_source")?,
                function_name: row.try_get("function_name")?,
                device_name: row.try_get("device_name")?,
                position: row.try_get("position")?,
                required: row.try_get::<_, i64>("required")? != 0,
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        admin: Client,
        schema: String,
        catalog: PostgresCatalog,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let dsn = env::var("TEST_DATABASE_URL").map_err(|_| Error::InvalidInput {
                field: "TEST_DATABASE_URL".into(),
                message: "PostgreSQL fixture tests require an authorized off-machine test database"
                    .into(),
            })?;
            let mut catalog = PostgresCatalog::new(&dsn)?;
            let mut admin = catalog.connect()?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| Error::Knowledge(error.to_string()))?
                .as_nanos();
            let schema = format!("sf_test_{}_{}", std::process::id(), stamp);
            admin.batch_execute(&format!("CREATE SCHEMA {schema}"))?;
            catalog.config.options(&format!("-c search_path={schema}"));
            let fixture = Self {
                admin,
                schema,
                catalog,
            };
            let mut connection = fixture.catalog.connect()?;
            let sql = include_str!("../tests/fixtures/schema.sql")
                .replace(
                    "INTEGER PRIMARY KEY",
                    "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
                )
                .replace(" INTEGER", " BIGINT");
            connection.batch_execute(&sql)?;
            connection.batch_execute(
                "INSERT INTO functions (source, interface, name, convention)
                 VALUES ('BUILT-IN', 'SSH', 'SENDSTR', 1);
                 INSERT INTO parameter_definitions (name, device_name, required, value_pattern)
                 VALUES ('DATA', 'SSH', 1, '<data>');
                 INSERT INTO criteria_definitions (name) VALUES ('EXPECTED');
                 INSERT INTO parameter_links (function_source, function_name, device_name, name, required)
                 VALUES ('BUILT-IN', 'SENDSTR', 'SSH', 'DATA', 1);
                 INSERT INTO criteria_links (function_source, function_name, name, position)
                 VALUES ('BUILT-IN', 'SENDSTR', 'EXPECTED', 2);
                 INSERT INTO examples (function_source, function_name, script)
                 VALUES ('BUILT-IN', 'SENDSTR', 'SSH|SENDSTR|payload|NULL|1');
                 ALTER TABLE functions RENAME TO functions_data;
                 CREATE FUNCTION require_snapshot_mode() RETURNS TEXT LANGUAGE plpgsql AS $$
                 BEGIN
                     IF current_setting('transaction_read_only') <> 'on'
                        OR current_setting('transaction_isolation') <> 'repeatable read' THEN
                         RAISE EXCEPTION 'catalog snapshot must be read-only and repeatable-read';
                     END IF;
                     RETURN 'BUILT-IN';
                 END;
                 $$;
                 CREATE VIEW functions AS
                 SELECT id, require_snapshot_mode() AS source, interface, name, description,
                        convention, category, execution_role, execution_phase, created_at, updated_at
                 FROM functions_data;",
            )?;
            Ok(fixture)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self
                .admin
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }

    #[test]
    fn postgres_snapshot_is_read_only_repeatable_and_maps_catalog_rows() -> Result<()> {
        let fixture = Fixture::new()?;
        let snapshot = fixture.catalog.snapshot()?;
        assert_eq!(snapshot.functions.len(), 1);
        assert_eq!(snapshot.functions[0].convention, Some(1));
        assert_eq!(snapshot.parameter_definitions.len(), 1);
        assert!(snapshot.parameter_definitions[0].required);
        assert_eq!(snapshot.parameter_definitions[0].default_value, None);
        assert_eq!(snapshot.criteria_definitions.len(), 1);
        assert_eq!(snapshot.parameter_links.len(), 1);
        assert_eq!(snapshot.parameter_links[0].position, None);
        assert!(snapshot.parameter_links[0].required);
        assert_eq!(snapshot.criteria_links[0].position, Some(2));
        assert_eq!(snapshot.examples.len(), 1);
        Ok(())
    }

    #[test]
    fn invalid_connection_errors_do_not_echo_credentials() {
        let result = PostgresCatalog::new(
            "postgres://user:do-not-echo@localhost/catalog?sslmode=unexpected",
        );
        let Err(error) = result else {
            panic!("invalid TLS mode was accepted");
        };
        assert!(!error.to_string().contains("do-not-echo"));
    }
}
