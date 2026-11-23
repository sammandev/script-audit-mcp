#![cfg(all(feature = "database", feature = "mcp"))]

use std::process::Command;

fn without_database_url() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_script-audit-mcp"));
    command.env_remove("SCRIPT_AUDIT_DATABASE_URL");
    command.env_remove("DATABASE_URL");
    command
}

#[test]
fn startup_requires_database_url() -> std::io::Result<()> {
    let output = without_database_url().output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected startup to fail, got {}; stderr: {stderr:?}",
        output.status
    );
    assert!(stderr.contains("SCRIPT_AUDIT_DATABASE_URL or DATABASE_URL"));
    Ok(())
}

#[test]
fn help_does_not_require_database_url() -> std::io::Result<()> {
    let output = without_database_url().arg("--help").output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
