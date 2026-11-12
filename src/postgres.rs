use std::{collections::BTreeMap, env, fs, time::Duration};

use native_tls::{Certificate, Protocol, TlsConnector};
use postgres::{Client, Config, IsolationLevel, NoTls, Row, Transaction, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use url::Url;

use crate::{
    Catalog, Error, Result,
    model::{AuditedGrammar, Definition, Example, Function, Link, ScriptKeyAudit, Snapshot},
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
        // Catalogs carrying the web ADR-0012 contract expose `mcp_v1_*` views
        // with audited grammar; older catalogs fall back to the base tables
        // and the built-in grammar profiles.
        let contract: bool = transaction
            .query_one("SELECT to_regclass('mcp_v1_functions') IS NOT NULL", &[])?
            .try_get(0)?;
        let prefix = if contract { "mcp_v1_" } else { "" };
        let grammar_columns = if contract {
            ", grammar_encoding, grammar_scope"
        } else {
            ""
        };
        let mut functions = rows(
            &mut transaction,
            &format!(
                "SELECT source, interface, name, description, convention, category, execution_role, execution_phase{grammar_columns} FROM {prefix}functions ORDER BY source, interface, name"
            ),
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
                    audited_grammar: if contract {
                        Some(AuditedGrammar {
                            encoding: row.try_get("grammar_encoding")?,
                            scope: row.try_get("grammar_scope")?,
                            script_keys: Vec::new(),
                        })
                    } else {
                        None
                    },
                })
            },
        )?;
        if contract {
            let audits = rows(
                &mut transaction,
                "SELECT function_source, function_interface, function_name, kind, name, scope FROM mcp_v1_script_key_audits ORDER BY function_source, function_interface, function_name, kind, name",
                |row| {
                    Ok((
                        (
                            row.try_get::<_, String>("function_source")?,
                            row.try_get::<_, String>("function_interface")?,
                            row.try_get::<_, String>("function_name")?,
                        ),
                        ScriptKeyAudit {
                            criterion: row.try_get::<_, String>("kind")? == "criterion",
                            name: row.try_get("name")?,
                            scope: row.try_get("scope")?,
                        },
                    ))
                },
            )?;
            let mut by_function: BTreeMap<(String, String, String), Vec<ScriptKeyAudit>> =
                BTreeMap::new();
            for (key, audit) in audits {
                by_function.entry(key).or_default().push(audit);
            }
            for function in &mut functions {
                if let Some(grammar) = &mut function.audited_grammar
                    && let Some(keys) = by_function.remove(&(
                        function.source.clone(),
                        function.interface.clone(),
                        function.name.clone(),
                    ))
                {
                    grammar.script_keys = keys;
                }
            }
        }
        let parameter_definitions =
            definitions(&mut transaction, &format!("{prefix}parameter_definitions"))?;
        let criteria_definitions =
            definitions(&mut transaction, &format!("{prefix}criteria_definitions"))?;
        let parameter_links = links(&mut transaction, &format!("{prefix}parameter_links"))?;
        let criteria_links = links(&mut transaction, &format!("{prefix}criteria_links"))?;
        let examples = rows(
            &mut transaction,
            &format!(
                "SELECT function_source, device_name, function_name, script, meaning FROM {prefix}examples ORDER BY id"
            ),
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
    use std::{
        io::{Read, Write},
        process::{Child, Command, Stdio},
    };

    struct Fixture {
        admin: Client,
        schema: String,
        catalog: PostgresCatalog,
    }

    impl Fixture {
        fn empty() -> Result<Self> {
            let dsn = env::var("TEST_DATABASE_URL").map_err(|_| Error::InvalidInput {
                field: "TEST_DATABASE_URL".into(),
                message: "PostgreSQL fixture tests require an authorized disposable test database"
                    .into(),
            })?;
            let mut catalog = PostgresCatalog::new(&dsn)?;
            let mut admin = catalog.connect()?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| Error::Knowledge(error.to_string()))?
                .as_nanos();
            // Parallel tests can read the same coarse Windows clock tick.
            static NEXT_SCHEMA: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let sequence = NEXT_SCHEMA.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let schema = format!("sf_test_{}_{}_{}", std::process::id(), stamp, sequence);
            admin.batch_execute(&format!("CREATE SCHEMA {schema}"))?;
            catalog.config.options(&format!("-c search_path={schema}"));
            Ok(Self {
                admin,
                schema,
                catalog,
            })
        }

        fn new() -> Result<Self> {
            let fixture = Self::empty()?;
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

        fn new_web_contract() -> Result<Self> {
            let fixture = Self::empty()?;
            let migration_dir =
                env::var("WEB_POSTGRES_MIGRATIONS_DIR").map_err(|_| Error::InvalidInput {
                    field: "WEB_POSTGRES_MIGRATIONS_DIR".into(),
                    message: "set this to the web repository's postgres_migrations directory"
                        .into(),
                })?;
            let mut migrations = Vec::new();
            for entry in fs::read_dir(&migration_dir)? {
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_file()
                    || path.extension().and_then(|extension| extension.to_str()) != Some("sql")
                {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let version = name
                    .split_once('_')
                    .map(|(version, _)| version)
                    .ok_or_else(|| Error::Knowledge(format!("invalid migration filename: {name}")))?
                    .parse::<i32>()
                    .map_err(|error| {
                        Error::Knowledge(format!("invalid migration version in {name}: {error}"))
                    })?;
                migrations.push((version, name, path));
            }
            migrations.sort_by_key(|(version, _, _)| *version);
            if migrations.is_empty() {
                return Err(Error::Knowledge(format!(
                    "no PostgreSQL migration SQL files found in {migration_dir}"
                )));
            }
            for pair in migrations.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(Error::Knowledge(format!(
                        "duplicate PostgreSQL migration version {}",
                        pair[0].0
                    )));
                }
            }

            let mut connection = fixture.catalog.connect()?;
            connection.batch_execute(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )",
            )?;
            for (version, name, path) in migrations {
                let sql = fs::read_to_string(path)?;
                connection.batch_execute(&sql)?;
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at)
                     VALUES ($1, $2, 'fixture')",
                    &[&version, &name],
                )?;
            }
            Ok(fixture)
        }

        fn web_database_url(&self) -> Result<String> {
            let dsn = env::var("TEST_DATABASE_URL").map_err(|_| Error::InvalidInput {
                field: "TEST_DATABASE_URL".into(),
                message: "set this to an authorized disposable test database".into(),
            })?;
            let mut url = Url::parse(&dsn).map_err(|_| Error::InvalidInput {
                field: "TEST_DATABASE_URL".into(),
                message: "expected a PostgreSQL URL".into(),
            })?;
            let mut pairs = url
                .query_pairs()
                .filter(|(key, _)| key != "search_path")
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            url.query_pairs_mut().clear();
            for (key, value) in pairs.drain(..) {
                url.query_pairs_mut().append_pair(&key, &value);
            }
            url.query_pairs_mut()
                .append_pair("search_path", &self.schema);
            Ok(url.to_string())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self
                .admin
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }

    struct WebApi {
        child: Child,
        address: String,
    }

    impl WebApi {
        fn start(binary: &std::ffi::OsStr, database_url: &str) -> Result<Self> {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?.to_string();
            drop(listener);
            let child = Command::new(binary)
                .arg("--addr")
                .arg(&address)
                .env("DATABASE_URL", database_url)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let mut api = Self { child, address };
            api.wait_until_ready()?;
            Ok(api)
        }

        fn wait_until_ready(&mut self) -> Result<()> {
            let mut last_error = "no health response".to_string();
            for _ in 0..50 {
                if let Some(status) = self.child.try_wait()? {
                    return Err(Error::Knowledge(format!(
                        "web API exited before becoming ready ({status})"
                    )));
                }
                match http_get(&self.address, "/health") {
                    Ok((200, body)) if body.contains("\"status\":\"ok\"") => return Ok(()),
                    Ok((status, _)) => {
                        last_error = format!("health endpoint returned HTTP {status}")
                    }
                    Err(error) => last_error = error.to_string(),
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(Error::Knowledge(format!(
                "web API did not become ready: {last_error}"
            )))
        }

        fn readiness(&self) -> Result<serde_json::Value> {
            let (status, body) = http_get(&self.address, "/api/mcp-readiness")?;
            if status != 200 {
                return Err(Error::Knowledge(format!(
                    "web readiness endpoint returned HTTP {status}"
                )));
            }
            serde_json::from_str(&body)
                .map_err(|error| Error::Knowledge(format!("invalid readiness JSON: {error}")))
        }
    }

    impl Drop for WebApi {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn http_get(address: &str, path: &str) -> Result<(u16, String)> {
        let socket = address
            .parse()
            .map_err(|error| Error::Knowledge(format!("invalid loopback address: {error}")))?;
        let mut stream = std::net::TcpStream::connect_timeout(&socket, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
        )?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let response = String::from_utf8(response)
            .map_err(|error| Error::Knowledge(format!("invalid HTTP response: {error}")))?;
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| Error::Knowledge("malformed HTTP response".into()))?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| Error::Knowledge("missing HTTP status".into()))?
            .parse::<u16>()
            .map_err(|error| Error::Knowledge(format!("invalid HTTP status: {error}")))?;
        Ok((status, body.to_string()))
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
        assert!(snapshot.functions[0].audited_grammar.is_none());
        Ok(())
    }

    #[test]
    fn postgres_snapshot_reads_mcp_v1_contract_grammar() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut connection = fixture.catalog.connect()?;
        connection.batch_execute(
            // The fixture's `functions` view reports every source as BUILT-IN
            // (snapshot-mode guard), so grammar rows use that source too.
            "INSERT INTO functions_data (source, interface, name, convention)
             VALUES ('DLL', 'WIFI_TEST', 'TX_MULTI_VERIFICATION', 2);
             CREATE TABLE function_grammars (function_source TEXT, function_interface TEXT,
                 function_name TEXT, encoding TEXT, scope TEXT);
             INSERT INTO function_grammars VALUES ('BUILT-IN', 'WIFI_TEST', 'TX_MULTI_VERIFICATION', 'named', 'line');
             CREATE VIEW mcp_v1_functions AS
             SELECT f.source, f.interface, f.name, f.description, f.convention, f.category,
                    f.execution_role, f.execution_phase,
                    COALESCE(g.encoding, '') AS grammar_encoding, COALESCE(g.scope, '') AS grammar_scope
             FROM functions f LEFT JOIN function_grammars g
               ON g.function_source = f.source AND g.function_interface = f.interface
              AND g.function_name = f.name;
             CREATE VIEW mcp_v1_script_key_audits AS
             SELECT 'BUILT-IN'::TEXT AS function_source, 'WIFI_TEST'::TEXT AS function_interface,
                    'TX_MULTI_VERIFICATION'::TEXT AS function_name, 'parameter'::TEXT AS kind,
                    'ANT'::TEXT AS name, 'line'::TEXT AS scope;
             CREATE VIEW mcp_v1_parameter_definitions AS SELECT * FROM parameter_definitions;
             CREATE VIEW mcp_v1_criteria_definitions AS SELECT * FROM criteria_definitions;
             CREATE VIEW mcp_v1_parameter_links AS SELECT * FROM parameter_links;
             CREATE VIEW mcp_v1_criteria_links AS SELECT * FROM criteria_links;
             CREATE VIEW mcp_v1_examples AS SELECT * FROM examples;",
        )?;
        let snapshot = fixture.catalog.snapshot()?;
        assert_eq!(snapshot.functions.len(), 2);
        let tx = snapshot
            .functions
            .iter()
            .find(|function| function.name == "TX_MULTI_VERIFICATION")
            .ok_or_else(|| Error::Knowledge("missing TX row".into()))?;
        assert_eq!(
            tx.audited_grammar,
            Some(AuditedGrammar {
                encoding: "named".into(),
                scope: "line".into(),
                script_keys: vec![ScriptKeyAudit {
                    criterion: false,
                    name: "ANT".into(),
                    scope: "line".into(),
                }],
            })
        );
        let ssh = snapshot
            .functions
            .iter()
            .find(|function| function.name == "SENDSTR")
            .ok_or_else(|| Error::Knowledge("missing SSH row".into()))?;
        assert_eq!(
            ssh.audited_grammar,
            Some(AuditedGrammar::default()),
            "unaudited rows must not fall back to built-in profiles"
        );
        assert_eq!(snapshot.parameter_links.len(), 1);
        assert_eq!(snapshot.examples.len(), 1);
        Ok(())
    }

    #[test]
    fn postgres_snapshot_reads_real_mcp_v1_views() -> Result<()> {
        let fixture = Fixture::new_web_contract()?;
        let mut connection = fixture.catalog.connect()?;
        connection.batch_execute(
            "INSERT INTO functions (source, interface, name, convention, created_at, updated_at)
             VALUES
                 ('DLL', 'WIFI_TEST', 'TX_MULTI_VERIFICATION', 2, 'fixture', 'fixture'),
                 ('DLL', 'WIFI_TEST', 'DUPLICATE', 2, 'fixture', 'fixture'),
                 ('DLL', 'IOT', 'DUPLICATE', 2, 'fixture', 'fixture');
             INSERT INTO parameter_definitions (
                 name, device_name, type, cardinality, value_pattern, required, created_at, updated_at
             ) VALUES ('ANT', 'WIFI_TEST', 'int', 'MULTIPLE', '<ant>', 1, 'fixture', 'fixture');
             INSERT INTO criteria_definitions (
                 name, device_name, type, cardinality, value_pattern, created_at, updated_at
             ) VALUES ('POWER', 'WIFI_TEST', 'double', 'SINGLE', '<power>', 'fixture', 'fixture');
             INSERT INTO parameter_links (
                 function_source, function_name, device_name, name, position, required,
                 created_at, updated_at
             ) VALUES
                 ('DLL', 'TX_MULTI_VERIFICATION', 'WIFI_TEST', 'ANT', 1, 1, 'fixture', 'fixture'),
                 ('DLL', 'DUPLICATE', '', 'ANT', 1, 1, 'fixture', 'fixture');
             INSERT INTO criteria_links (
                 function_source, function_name, device_name, name, position, required,
                 created_at, updated_at
             ) VALUES ('DLL', 'TX_MULTI_VERIFICATION', 'WIFI_TEST', 'POWER', 2, 0, 'fixture', 'fixture');
             INSERT INTO examples (
                 function_source, function_name, device_name, script, meaning, created_at, updated_at
             ) VALUES
                 ('DLL', 'TX_MULTI_VERIFICATION', 'WIFI_TEST', 'DLLWIFI_TEST|TX_MULTI_VERIFICATION', 'unique', 'fixture', 'fixture'),
                 ('DLL', 'DUPLICATE', '', 'DLLWIFI_TEST|DUPLICATE', 'ambiguous', 'fixture', 'fixture');",
        )?;

        let snapshot = fixture.catalog.snapshot()?;
        assert_eq!(snapshot.functions.len(), 3);
        assert_eq!(snapshot.parameter_definitions.len(), 1);
        assert_eq!(snapshot.criteria_definitions.len(), 1);
        assert_eq!(snapshot.parameter_links.len(), 2);
        assert_eq!(snapshot.criteria_links.len(), 1);
        assert_eq!(snapshot.examples.len(), 2);

        let tx = snapshot
            .functions
            .iter()
            .find(|function| function.name == "TX_MULTI_VERIFICATION")
            .ok_or_else(|| Error::Knowledge("missing TX row".into()))?;
        let grammar = tx
            .audited_grammar
            .as_ref()
            .ok_or_else(|| Error::Knowledge("missing audited grammar".into()))?;
        assert_eq!(grammar.encoding, "named");
        assert_eq!(grammar.scope, "line");
        assert!(
            grammar
                .script_keys
                .iter()
                .any(|audit| { !audit.criterion && audit.name == "ANT" && audit.scope == "line" })
        );
        assert_eq!(snapshot.parameter_definitions[0].name, "ANT");
        assert!(snapshot.parameter_definitions[0].required);
        assert_eq!(snapshot.criteria_definitions[0].name, "POWER");
        assert_eq!(
            snapshot.parameter_links[0].function_name,
            "TX_MULTI_VERIFICATION"
        );
        assert_eq!(snapshot.criteria_links[0].name, "POWER");
        assert_eq!(snapshot.examples[0].meaning, "unique");

        let unique_link_interface: String = connection
            .query_one(
                "SELECT function_interface FROM mcp_v1_parameter_links
                 WHERE function_name = 'TX_MULTI_VERIFICATION'",
                &[],
            )?
            .try_get(0)?;
        let ambiguous_link_interface: String = connection
            .query_one(
                "SELECT function_interface FROM mcp_v1_parameter_links
                 WHERE function_name = 'DUPLICATE'",
                &[],
            )?
            .try_get(0)?;
        let unique_example_interface: String = connection
            .query_one(
                "SELECT function_interface FROM mcp_v1_examples
                 WHERE function_name = 'TX_MULTI_VERIFICATION'",
                &[],
            )?
            .try_get(0)?;
        let ambiguous_example_interface: String = connection
            .query_one(
                "SELECT function_interface FROM mcp_v1_examples
                 WHERE function_name = 'DUPLICATE'",
                &[],
            )?
            .try_get(0)?;
        assert_eq!(unique_link_interface, "WIFI_TEST");
        assert_eq!(ambiguous_link_interface, "");
        assert_eq!(unique_example_interface, "WIFI_TEST");
        assert_eq!(ambiguous_example_interface, "");
        Ok(())
    }

    #[test]
    #[ignore = "run via deploy/mcp-parity.py against a disposable test database"]
    fn postgres_readiness_matches_mcp_list_functions() -> Result<()> {
        let binary = env::var_os("WEB_API_BINARY").ok_or_else(|| Error::InvalidInput {
            field: "WEB_API_BINARY".into(),
            message: "run this test through deploy/mcp-parity.py".into(),
        })?;
        let fixture = Fixture::new_web_contract()?;
        let mut connection = fixture.catalog.connect()?;
        connection.batch_execute(
            "INSERT INTO functions (source, interface, name, convention, created_at, updated_at)
             VALUES
                 ('DLL', 'WIFI_TEST', 'TX_MULTI_VERIFICATION', 2, 'fixture', 'fixture'),
                 ('DLL', 'WIFI_TEST', 'RX_VERIFY_PER', 2, 'fixture', 'fixture'),
                 ('DLL', 'WIFI_TEST', 'NOT_AUDITED', 2, 'fixture', 'fixture'),
                 ('DLL', 'WIFI_TEST', 'DUPLICATE', 2, 'fixture', 'fixture'),
                 ('DLL', 'IOT', 'DUPLICATE', 2, 'fixture', 'fixture');",
        )?;
        let api = WebApi::start(&binary, &fixture.web_database_url()?)?;
        let readiness = api.readiness()?;
        let items = readiness
            .get("items")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::Knowledge("readiness response has no items array".into()))?;
        let mut web_status = BTreeMap::new();
        for item in items {
            let source = item
                .get("source")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Knowledge("readiness item has no source".into()))?;
            let interface = item
                .get("interface")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Knowledge("readiness item has no interface".into()))?;
            let name = item
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Knowledge("readiness item has no name".into()))?;
            let status = item
                .get("status")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Knowledge("readiness item has no status".into()))?;
            web_status.insert(
                (source.to_string(), interface.to_string(), name.to_string()),
                status.to_string(),
            );
        }

        let engine = crate::Engine::new(fixture.catalog.snapshot()?);
        let mcp_functions = engine.list_functions(None)?;
        let mcp_support = mcp_functions
            .into_iter()
            .map(|function| {
                (
                    (function.source, function.interface, function.name),
                    function.composition_supported,
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(web_status.len(), mcp_support.len());
        for (key, status) in &web_status {
            let supported = mcp_support
                .get(key)
                .ok_or_else(|| Error::Knowledge(format!("MCP is missing Function {key:?}")))?;
            assert_eq!(
                status == "ready",
                *supported,
                "readiness mismatch for {key:?}: web status {status}"
            );
        }
        assert_eq!(
            web_status.get(&(
                "DLL".to_string(),
                "WIFI_TEST".to_string(),
                "TX_MULTI_VERIFICATION".to_string(),
            )),
            Some(&"ready".to_string())
        );
        assert_eq!(
            web_status.get(&(
                "DLL".to_string(),
                "WIFI_TEST".to_string(),
                "RX_VERIFY_PER".to_string(),
            )),
            Some(&"bundle_ready".to_string())
        );
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
