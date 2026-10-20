use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use script_checker::analysis::{AnalysisOutput, AnalysisRequest, analyze, list_flows};
use script_checker::cli::{
    BatchArgs, CheckArgs, Cli, Commands, FlowsArgs, Format, View, help_text,
};
use script_checker::local_time::local_iso8601;
use script_checker::models::ScriptInfo;
use script_checker::output::{
    BatchDiagnosticSummary, BatchRunResult, BatchRunSummary, render_analysis_xlsx,
    render_batch_summary_json, render_batch_summary_xlsx, render_csv, render_flows_csv,
    render_json, render_list_flows_json, render_list_flows_xlsx, render_text, render_text_concise,
    render_text_detailed, render_text_pass_fail_compact, render_text_pass_fail_detailed,
    render_text_path_summary, render_text_syntax, render_text_validation,
};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let cli = Cli::parse_env()?;
    match cli.command {
        Commands::Help => {
            print!("{}", help_text());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Flows(args) => run_flows(args),
        Commands::Check(args) => run_check(args),
        Commands::Batch(args) => run_batch(args),
    }
}

fn emit(text: &str, out: Option<&PathBuf>) -> Result<(), String> {
    match out {
        Some(path) => std::fs::write(path, text)
            .map_err(|error| format!("failed to write {}: {error}", path.display())),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

fn emit_binary(bytes: &[u8], out: Option<&PathBuf>, format: &str) -> Result<(), String> {
    match out {
        Some(path) => std::fs::write(path, bytes)
            .map_err(|error| format!("failed to write {}: {error}", path.display())),
        None => Err(format!("--format {format} requires --out <PATH>")),
    }
}

fn run_flows(args: FlowsArgs) -> Result<ExitCode, String> {
    let headers = list_flows(&args.main_flow)?;
    if args.format == Format::Xlsx {
        let workbook = render_list_flows_xlsx(&headers);
        emit_binary(&workbook, args.out.as_ref(), "xlsx")?;
        return Ok(ExitCode::SUCCESS);
    }
    let text = match args.format {
        Format::Json => render_list_flows_json(&headers),
        Format::Csv => render_flows_csv(&headers),
        Format::Text => {
            let mut text = String::new();
            for header in &headers {
                text.push_str(header);
                text.push('\n');
            }
            text
        }
        Format::Xlsx => unreachable!(),
    };
    emit(&text, args.out.as_ref())?;
    Ok(ExitCode::SUCCESS)
}

fn run_check(args: CheckArgs) -> Result<ExitCode, String> {
    let debug = args.debug;
    let format = args.format;
    let view = args.view;
    let request = AnalysisRequest {
        scripts_root: args.scripts_root,
        main_flow: args.main_flow,
        macro_list: args.macro_list,
        flow_header: args.flow_header,
    };
    let output = analyze(request)?;
    if format == Format::Xlsx {
        let workbook = render_analysis_xlsx(&output);
        emit_binary(&workbook, args.out.as_ref(), "xlsx")?;
        return Ok(if output.status == "ok" {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    let text = match format {
        Format::Json => render_json(&output, debug),
        Format::Csv => render_csv(&output),
        Format::Text => render_view_text(&output, view),
        Format::Xlsx => unreachable!(),
    };
    emit(&text, args.out.as_ref())?;
    Ok(if output.status == "ok" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn run_batch(args: BatchArgs) -> Result<ExitCode, String> {
    std::fs::create_dir_all(&args.out_dir)
        .map_err(|error| format!("failed to create {}: {error}", args.out_dir.display()))?;
    let main_flow = args.scripts_root.join("MAIN_FLOW.ini");
    let headers = list_flows(&main_flow)?;
    if headers.is_empty() {
        return Err(format!(
            "no TEST FLOW sections were found in {}",
            main_flow.display()
        ));
    }

    let bundle = bundle_name(&args.scripts_root);
    let mut checked_flows = 0usize;
    let mut reported_results = Vec::new();
    let mut diagnostics = Vec::new();
    let mut seen_diagnostics = HashSet::new();
    let mut status_counts = BTreeMap::new();
    let mut script_info = ScriptInfo::default();

    for header in headers {
        let stem = format!("{}_{}", safe_name(&bundle), safe_name(&header));
        let json_path = args.out_dir.join(format!("{stem}.json"));
        let text_path = args.out_dir.join(format!("{stem}.txt"));
        let output = analyze(AnalysisRequest {
            scripts_root: Some(args.scripts_root.clone()),
            main_flow: None,
            macro_list: None,
            flow_header: Some(header.clone()),
        })?;
        checked_flows += 1;
        if script_info_is_empty(&script_info) {
            script_info = output.script_info.clone();
        }
        std::fs::write(&json_path, render_json(&output, args.debug))
            .map_err(|error| format!("failed to write {}: {error}", json_path.display()))?;
        std::fs::write(&text_path, render_view_text(&output, args.view))
            .map_err(|error| format!("failed to write {}: {error}", text_path.display()))?;

        if is_reported_status(&output.status) {
            add_status(&mut status_counts, &output.status);
        }

        for diagnostic in &output.diagnostics {
            let key = format!(
                "{}|{}|{}|{}|{}|{}",
                diagnostic.severity.as_str(),
                diagnostic.code,
                diagnostic.file,
                diagnostic.line,
                diagnostic.message,
                diagnostic.evidence
            );
            if seen_diagnostics.insert(key) {
                diagnostics.push(BatchDiagnosticSummary {
                    severity: diagnostic.severity.as_str().to_string(),
                    code: diagnostic.code.clone(),
                    file: diagnostic.file.clone(),
                    line: diagnostic.line,
                    message: diagnostic.message.clone(),
                    evidence: diagnostic.evidence.clone(),
                });
            }
        }

        if is_reported_status(&output.status) {
            reported_results.push(BatchRunResult {
                created_at: output.created_at,
                header,
                status: output.status,
                errors: output.counts.errors,
                warnings: output.counts.warnings,
                path_issues: output.counts.issues,
                json_path: path_string(&json_path),
                text_path: path_string(&text_path),
            });
        }
    }

    diagnostics.sort_by(|left, right| {
        (left.severity.as_str(), left.code.as_str(), left.line).cmp(&(
            right.severity.as_str(),
            right.code.as_str(),
            right.line,
        ))
    });

    let summary = BatchRunSummary {
        created_at: local_iso8601(),
        tool_name: "script-checker".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        scripts_root: path_string(&args.scripts_root),
        output_root: path_string(&args.out_dir),
        script_info,
        checked_flows,
        reported_flows: reported_results.len(),
        status: status_counts,
        results: reported_results,
        diagnostics,
    };

    let summary_json = args.out_dir.join("summary.json");
    let summary_xlsx = args.out_dir.join("summary.xlsx");
    std::fs::write(&summary_json, render_batch_summary_json(&summary))
        .map_err(|error| format!("failed to write {}: {error}", summary_json.display()))?;
    std::fs::write(&summary_xlsx, render_batch_summary_xlsx(&summary))
        .map_err(|error| format!("failed to write {}: {error}", summary_xlsx.display()))?;

    print_batch_output(&summary, &summary_json, &summary_xlsx, args.view);

    Ok(if summary.reported_flows == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn render_view_text(output: &AnalysisOutput, view: View) -> String {
    match view {
        View::Standard => render_text(output),
        View::Brief => render_text_concise(output),
        View::Full => render_text_detailed(output),
        View::Paths => render_text_path_summary(output),
        View::PassFail => render_text_pass_fail_compact(output),
        View::PassFailFull => render_text_pass_fail_detailed(output),
        View::Syntax => render_text_syntax(output),
        View::Ci => render_text_validation(output),
    }
}

fn print_batch_output(
    summary: &BatchRunSummary,
    summary_json: &Path,
    summary_xlsx: &Path,
    view: View,
) {
    match view {
        View::Brief => {
            println!(
                "Checked {} flow(s), non-clean {}. Summary: {}",
                summary.checked_flows,
                summary.reported_flows,
                summary_json.display()
            );
        }
        View::Full => {
            println!("script-checker batch");
            println!("Scripts root: {}", summary.scripts_root);
            println!("Output root: {}", summary.output_root);
            println!("Summary JSON: {}", summary_json.display());
            println!("Summary XLSX: {}", summary_xlsx.display());
            println!(
                "Checked: {}; non-clean: {}",
                summary.checked_flows, summary.reported_flows
            );
            if summary.status.is_empty() {
                println!("Status counts: all clean");
            } else {
                println!("Status counts:");
                for (status, count) in &summary.status {
                    println!("  {status}: {count}");
                }
            }
            if summary.results.is_empty() {
                println!("Non-clean flows: none");
            } else {
                println!("Non-clean flows:");
                for result in &summary.results {
                    println!(
                        "  {} -> status={}, errors={}, warnings={}, path_issues={}",
                        result.header,
                        result.status,
                        result.errors,
                        result.warnings,
                        result.path_issues
                    );
                    println!("    JSON: {}", result.json_path);
                    println!("    Text: {}", result.text_path);
                }
            }
        }
        _ => {
            println!("Wrote {}", summary_json.display());
            println!("Wrote {}", summary_xlsx.display());
            println!(
                "Checked {} flow(s); reported {} non-clean flow(s).",
                summary.checked_flows, summary.reported_flows
            );
        }
    }
}

fn bundle_name(scripts_root: &Path) -> String {
    scripts_root
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("bundle")
        .to_string()
}

fn safe_name(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if safe.is_empty() {
        "report".to_string()
    } else {
        safe
    }
}

fn add_status(counts: &mut BTreeMap<String, usize>, status: &str) {
    *counts.entry(status.to_string()).or_insert(0) += 1;
}

fn is_reported_status(status: &str) -> bool {
    let status = status.trim().to_ascii_lowercase();
    !status.is_empty() && status != "ok" && status != "good"
}

fn script_info_is_empty(script_info: &ScriptInfo) -> bool {
    script_info.script_version.is_none()
        && script_info.program_version.is_none()
        && script_info.ver.is_none()
        && script_info.model_name.is_none()
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
