use script_checker::analysis::{ContentAnalysisRequest, SourceFile, analyze_contents};

#[test]
fn consumes_structured_checker_results_without_a_database() -> Result<(), String> {
    let main = SourceFile {
        name: "MAIN_FLOW.ini".into(),
        text: concat!(
            "; retained reference\n",
            "[TEST FLOW:Normal]\nRUN = \"RUN\"\n[RUN]\n",
            "A = \"DLLQSPR#QUICK|FUNC|ANT=1|POWER=5dB|NULL|SET_IPLAS_INFO|FAIL\n",
        )
        .into(),
    };
    let report = analyze_contents(ContentAnalysisRequest {
        main_flow: main.clone(),
        macro_list: None,
        auxiliary_files: Vec::new(),
        required_files: vec!["FACTORY_SETTING.ini".into()],
        flow_header: "[TEST FLOW:Normal]".into(),
    })?;

    assert_eq!(report.status, "error");
    assert_eq!(report.counts.errors, 3);
    assert_eq!(report.source_files, vec![main]);
    let codes: Vec<_> = report
        .diagnostics
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert_eq!(
        codes,
        [
            "UNTERMINATED_QUOTE",
            "SCRIPT_FILE_MISSING",
            "BRANCH_TARGET_MISSING"
        ]
    );
    let row = &report.script_sections[0].rows[0];
    assert_eq!(row.line, 5);
    assert_eq!(row.dll_name, "DLLQSPR#QUICK");
    assert_eq!(row.criteria, "ANT=1");
    assert_eq!(row.parameters, "POWER=5dB");
    assert_eq!(row.pass_path, "SET_IPLAS_INFO");
    Ok(())
}
