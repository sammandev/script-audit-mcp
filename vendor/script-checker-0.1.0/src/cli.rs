use std::path::PathBuf;

pub struct Cli {
    pub command: Commands,
}

pub enum Commands {
    Help,
    Flows(FlowsArgs),
    Check(CheckArgs),
    Batch(BatchArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Csv,
    Xlsx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Standard,
    Brief,
    Full,
    Paths,
    PassFail,
    PassFailFull,
    Syntax,
    Ci,
}

pub struct FlowsArgs {
    pub main_flow: PathBuf,
    pub format: Format,
    pub out: Option<PathBuf>,
}

pub struct CheckArgs {
    pub scripts_root: Option<PathBuf>,
    pub main_flow: Option<PathBuf>,
    pub macro_list: Option<PathBuf>,
    pub flow_header: Option<String>,
    pub format: Format,
    pub view: View,
    pub out: Option<PathBuf>,
    pub debug: bool,
}

pub struct BatchArgs {
    pub scripts_root: PathBuf,
    pub out_dir: PathBuf,
    pub view: View,
    pub debug: bool,
}

impl Cli {
    pub fn parse_env() -> Result<Self, String> {
        Self::parse(std::env::args().skip(1).collect())
    }

    pub fn parse(mut args: Vec<String>) -> Result<Self, String> {
        if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
            return Ok(Self {
                command: Commands::Help,
            });
        }
        let command = args.remove(0);
        match command.as_str() {
            "flows" | "ls" => Ok(Self {
                command: Commands::Flows(parse_flows(args)?),
            }),
            "check" => Ok(Self {
                command: Commands::Check(parse_check(args, false)?),
            }),
            "debug" => Ok(Self {
                command: Commands::Check(parse_check(args, true)?),
            }),
            "batch" => Ok(Self {
                command: Commands::Batch(parse_batch(args, false)?),
            }),
            "batch-debug" => Ok(Self {
                command: Commands::Batch(parse_batch(args, true)?),
            }),
            value => Err(format!("unknown command '{value}'\n\n{}", help_text())),
        }
    }
}

fn parse_format(value: &str) -> Result<Format, String> {
    match value {
        "text" | "txt" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        "csv" => Ok(Format::Csv),
        "xlsx" => Ok(Format::Xlsx),
        other => Err(format!(
            "unknown --format '{other}' (use text, json, csv, or xlsx)"
        )),
    }
}

fn parse_view(value: &str) -> Result<View, String> {
    match value {
        "standard" => Ok(View::Standard),
        "brief" => Ok(View::Brief),
        "full" => Ok(View::Full),
        "paths" => Ok(View::Paths),
        "pass-fail" => Ok(View::PassFail),
        "pass-fail-full" => Ok(View::PassFailFull),
        "syntax" => Ok(View::Syntax),
        "ci" => Ok(View::Ci),
        other => Err(format!(
            "unknown --view '{other}' (use standard, brief, full, paths, pass-fail, pass-fail-full, syntax, or ci)"
        )),
    }
}

fn next_value<'a>(args: &'a [String], cursor: &mut usize, flag: &str) -> Result<&'a str, String> {
    *cursor += 1;
    args.get(*cursor)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_flows(args: Vec<String>) -> Result<FlowsArgs, String> {
    let mut main_flow = None;
    let mut format = Format::Text;
    let mut out = None;
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].as_str() {
            "--main-flow" => {
                main_flow = Some(PathBuf::from(next_value(
                    &args,
                    &mut cursor,
                    "--main-flow",
                )?));
            }
            "--scripts-root" => {
                main_flow = Some(
                    PathBuf::from(next_value(&args, &mut cursor, "--scripts-root")?)
                        .join("MAIN_FLOW.ini"),
                );
            }
            "--format" | "-f" => {
                format = parse_format(next_value(&args, &mut cursor, "--format")?)?;
            }
            "--out" | "-o" => {
                out = Some(PathBuf::from(next_value(&args, &mut cursor, "--out")?));
            }
            other => return Err(format!("unexpected flows argument '{other}'")),
        }
        cursor += 1;
    }
    Ok(FlowsArgs {
        main_flow: main_flow.ok_or("flows requires --main-flow or --scripts-root")?,
        format,
        out,
    })
}

fn parse_check(args: Vec<String>, debug: bool) -> Result<CheckArgs, String> {
    let mut parsed = CheckArgs {
        scripts_root: None,
        main_flow: None,
        macro_list: None,
        flow_header: None,
        format: if debug { Format::Json } else { Format::Text },
        view: View::Standard,
        out: None,
        debug,
    };
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].as_str() {
            "--scripts-root" => {
                parsed.scripts_root = Some(PathBuf::from(next_value(
                    &args,
                    &mut cursor,
                    "--scripts-root",
                )?));
            }
            "--main-flow" => {
                parsed.main_flow = Some(PathBuf::from(next_value(
                    &args,
                    &mut cursor,
                    "--main-flow",
                )?));
            }
            "--macro-list" => {
                parsed.macro_list = Some(PathBuf::from(next_value(
                    &args,
                    &mut cursor,
                    "--macro-list",
                )?));
            }
            "--flow" | "--flow-header" => {
                parsed.flow_header = Some(next_value(&args, &mut cursor, "--flow")?.to_string());
            }
            "--format" | "-f" => {
                parsed.format = parse_format(next_value(&args, &mut cursor, "--format")?)?;
            }
            "--view" | "-v" => {
                parsed.view = parse_view(next_value(&args, &mut cursor, "--view")?)?;
            }
            "--out" | "-o" => {
                parsed.out = Some(PathBuf::from(next_value(&args, &mut cursor, "--out")?));
            }
            other => return Err(format!("unexpected check argument '{other}'")),
        }
        cursor += 1;
    }
    if parsed.scripts_root.is_none() && parsed.main_flow.is_none() {
        return Err("check requires --scripts-root or --main-flow".to_string());
    }
    Ok(parsed)
}

fn parse_batch(args: Vec<String>, debug: bool) -> Result<BatchArgs, String> {
    let mut scripts_root = None;
    let mut out_dir = None;
    let mut view = View::Standard;
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].as_str() {
            "--scripts-root" => {
                scripts_root = Some(PathBuf::from(next_value(
                    &args,
                    &mut cursor,
                    "--scripts-root",
                )?));
            }
            "--out-dir" | "--out" | "-o" => {
                out_dir = Some(PathBuf::from(next_value(&args, &mut cursor, "--out-dir")?));
            }
            "--view" | "-v" => {
                view = parse_view(next_value(&args, &mut cursor, "--view")?)?;
            }
            other => return Err(format!("unexpected batch argument '{other}'")),
        }
        cursor += 1;
    }
    Ok(BatchArgs {
        scripts_root: scripts_root.ok_or("batch requires --scripts-root")?,
        out_dir: out_dir.ok_or("batch requires --out-dir")?,
        view,
        debug,
    })
}

pub fn help_text() -> String {
    format!(
        "script-checker {version}

USAGE:
    script-checker flows --main-flow <MAIN_FLOW.ini> [--format text|json|csv|xlsx] [--out <PATH>]
  script-checker check (--scripts-root <DIR> | --main-flow <MAIN_FLOW.ini>) [--flow <HEADER>]
                                             [--macro-list <MACRO_LIST.ini>] [--format text|json|csv|xlsx] [--view <VIEW>] [--out <PATH>]
  script-checker batch --scripts-root <DIR> --out-dir <DIR> [--view <VIEW>]

COMMANDS:
  flows        List exact TEST FLOW headers (alias: ls)
  check        Check one flow; no graph debug payload
    batch        Check every flow in one bundle; writes summary.json, summary.xlsx, per-flow .json and .txt
  debug        Same as check, plus the full graph debug payload (JSON by default)
  batch-debug  Same as batch, with the full graph debug payload in per-flow JSON

OPTIONS:
    --format, -f  text (default), json, csv, xlsx
  --view, -v    standard (default), brief, full, paths, pass-fail, pass-fail-full, syntax, ci
  --out, -o     write the result to a file instead of stdout
  --out-dir     batch report folder
  --flow        exact TEST FLOW header
",
        version = env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn check_defaults_to_text_without_debug() {
        let cli = Cli::parse(args(&["check", "--scripts-root", "root"])).expect("parse");
        match cli.command {
            Commands::Check(parsed) => {
                assert_eq!(parsed.format, Format::Text);
                assert_eq!(parsed.view, View::Standard);
                assert!(!parsed.debug);
            }
            _ => panic!("expected check"),
        }
    }

    #[test]
    fn debug_command_enables_graph_payload() {
        let cli = Cli::parse(args(&["debug", "--main-flow", "MAIN_FLOW.ini"])).expect("parse");
        match cli.command {
            Commands::Check(parsed) => {
                assert!(parsed.debug);
                assert_eq!(parsed.format, Format::Json);
            }
            _ => panic!("expected check"),
        }
    }

    #[test]
    fn flows_accepts_scripts_root() {
        let cli = Cli::parse(args(&["ls", "--scripts-root", "root", "-f", "csv"])).expect("parse");
        match cli.command {
            Commands::Flows(parsed) => {
                assert!(parsed.main_flow.ends_with("MAIN_FLOW.ini"));
                assert_eq!(parsed.format, Format::Csv);
            }
            _ => panic!("expected flows"),
        }
    }

    #[test]
    fn unknown_format_is_rejected() {
        let error = match Cli::parse(args(&["check", "--main-flow", "f", "--format", "xml"])) {
            Ok(_) => panic!("expected error"),
            Err(error) => error,
        };
        assert!(error.contains("unknown --format"));
    }

    #[test]
    fn xlsx_format_is_accepted() {
        let cli = Cli::parse(args(&[
            "check",
            "--main-flow",
            "MAIN_FLOW.ini",
            "--format",
            "xlsx",
            "--out",
            "report.xlsx",
        ]))
        .expect("parse");
        match cli.command {
            Commands::Check(parsed) => assert_eq!(parsed.format, Format::Xlsx),
            _ => panic!("expected check"),
        }
    }
}
