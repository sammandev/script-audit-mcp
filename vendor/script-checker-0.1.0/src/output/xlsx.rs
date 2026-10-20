use super::{BatchRunSummary, count_pairs, opt_display, path_check_pairs};
use crate::analysis::AnalysisOutput;

struct XlsxSheet {
    name: String,
    rows: Vec<Vec<String>>,
}

impl XlsxSheet {
    fn new(name: &str, rows: Vec<Vec<String>>) -> Self {
        Self {
            name: name.to_string(),
            rows,
        }
    }
}

pub fn render_list_flows_xlsx(headers: &[String]) -> Vec<u8> {
    let mut rows = vec![row(["index", "flow_header"])];
    for (index, header) in headers.iter().enumerate() {
        rows.push(vec![(index + 1).to_string(), header.clone()]);
    }
    render_workbook(vec![XlsxSheet::new("Flows", rows)])
}

pub fn render_analysis_xlsx(output: &AnalysisOutput) -> Vec<u8> {
    let mut meta = key_value_rows();
    push_kv(&mut meta, "schema_version", &output.schema_version);
    push_kv(&mut meta, "created_at", &output.created_at);
    push_kv(&mut meta, "tool_name", &output.tool.name);
    push_kv(&mut meta, "tool_version", &output.tool.version);
    push_kv(&mut meta, "status", &output.status);
    push_kv(
        &mut meta,
        "script_root",
        output.inputs.script_root.as_deref().unwrap_or("-"),
    );
    push_kv(
        &mut meta,
        "main_flow",
        output.inputs.main_flow.as_deref().unwrap_or("-"),
    );
    push_kv(
        &mut meta,
        "macro_list",
        output.inputs.macro_list.as_deref().unwrap_or("-"),
    );
    push_kv(
        &mut meta,
        "flow_header",
        output.inputs.flow_header.as_deref().unwrap_or("-"),
    );
    push_script_info(&mut meta, &output.script_info);

    let mut counts = key_value_rows();
    for (name, value) in count_pairs(&output.counts) {
        push_kv(&mut counts, name, value.to_string());
    }

    let mut path_checks = key_value_rows();
    if let Some(graph) = &output.graph {
        push_kv(&mut path_checks, "status", &graph.status);
        push_kv(&mut path_checks, "flow_header", &graph.flow_header);
        for (name, value) in path_check_pairs(graph) {
            push_kv(&mut path_checks, name, value.to_string());
        }
    }

    let mut diagnostics = vec![row([
        "severity", "code", "file", "line", "message", "evidence",
    ])];
    for diagnostic in &output.diagnostics {
        diagnostics.push(vec![
            diagnostic.severity.as_str().to_string(),
            diagnostic.code.clone(),
            diagnostic.file.clone(),
            diagnostic.line.to_string(),
            diagnostic.message.clone(),
            diagnostic.evidence.clone(),
        ]);
    }

    let mut path_issues = vec![row([
        "type", "item", "label", "target", "message", "evidence", "detail",
    ])];
    if let Some(graph) = &output.graph {
        for issue in &graph.issues {
            path_issues.push(vec![
                issue.issue_type.clone(),
                issue.item.clone().unwrap_or_else(|| "-".to_string()),
                issue.label.clone().unwrap_or_else(|| "-".to_string()),
                issue.target.clone().unwrap_or_else(|| "-".to_string()),
                issue.message.clone(),
                issue.evidence.clone(),
                issue.detail.clone(),
            ]);
        }
    }

    render_workbook(vec![
        XlsxSheet::new("Meta", meta),
        XlsxSheet::new("Counts", counts),
        XlsxSheet::new("Path Checks", path_checks),
        XlsxSheet::new("Diagnostics", diagnostics),
        XlsxSheet::new("Path Issues", path_issues),
    ])
}

pub fn render_batch_summary_xlsx(summary: &BatchRunSummary) -> Vec<u8> {
    let mut meta = key_value_rows();
    push_kv(&mut meta, "created_at", &summary.created_at);
    push_kv(&mut meta, "tool_name", &summary.tool_name);
    push_kv(&mut meta, "tool_version", &summary.tool_version);
    push_kv(&mut meta, "scripts_root", &summary.scripts_root);
    push_kv(&mut meta, "output_root", &summary.output_root);
    push_script_info(&mut meta, &summary.script_info);

    let mut summary_rows = key_value_rows();
    push_kv(
        &mut summary_rows,
        "checked_flows",
        summary.checked_flows.to_string(),
    );
    push_kv(
        &mut summary_rows,
        "reported_flows",
        summary.reported_flows.to_string(),
    );

    let mut status = vec![row(["status", "count"])];
    for (name, count) in &summary.status {
        status.push(vec![name.clone(), count.to_string()]);
    }

    let mut results = vec![row([
        "created_at",
        "header",
        "status",
        "errors",
        "warnings",
        "path_issues",
        "json_path",
        "text_path",
    ])];
    for result in &summary.results {
        results.push(vec![
            result.created_at.clone(),
            result.header.clone(),
            result.status.clone(),
            result.errors.to_string(),
            result.warnings.to_string(),
            result.path_issues.to_string(),
            result.json_path.clone(),
            result.text_path.clone(),
        ]);
    }

    let mut diagnostics = vec![row([
        "severity", "code", "file", "line", "message", "evidence",
    ])];
    for diagnostic in &summary.diagnostics {
        diagnostics.push(vec![
            diagnostic.severity.clone(),
            diagnostic.code.clone(),
            diagnostic.file.clone(),
            diagnostic.line.to_string(),
            diagnostic.message.clone(),
            diagnostic.evidence.clone(),
        ]);
    }

    render_workbook(vec![
        XlsxSheet::new("Meta", meta),
        XlsxSheet::new("Summary", summary_rows),
        XlsxSheet::new("Status", status),
        XlsxSheet::new("Results", results),
        XlsxSheet::new("Diagnostics", diagnostics),
    ])
}

fn key_value_rows() -> Vec<Vec<String>> {
    vec![row(["key", "value"])]
}

fn push_kv(rows: &mut Vec<Vec<String>>, key: &str, value: impl Into<String>) {
    rows.push(vec![key.to_string(), value.into()]);
}

fn push_script_info(rows: &mut Vec<Vec<String>>, script_info: &crate::models::ScriptInfo) {
    push_kv(
        rows,
        "script_version",
        opt_display(&script_info.script_version),
    );
    push_kv(
        rows,
        "program_version",
        opt_display(&script_info.program_version),
    );
    push_kv(rows, "ver", opt_display(&script_info.ver));
    push_kv(rows, "model_name", opt_display(&script_info.model_name));
}

fn row<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn render_workbook(sheets: Vec<XlsxSheet>) -> Vec<u8> {
    let mut zip = StoredZip::new();
    zip.add(
        "[Content_Types].xml",
        content_types_xml(sheets.len()).as_bytes(),
    );
    zip.add("_rels/.rels", root_rels_xml().as_bytes());
    zip.add("xl/workbook.xml", workbook_xml(&sheets).as_bytes());
    zip.add(
        "xl/_rels/workbook.xml.rels",
        workbook_rels_xml(sheets.len()).as_bytes(),
    );
    for (index, sheet) in sheets.iter().enumerate() {
        let name = format!("xl/worksheets/sheet{}.xml", index + 1);
        zip.add(&name, worksheet_xml(sheet).as_bytes());
    }
    zip.finish()
}

fn content_types_xml(sheet_count: usize) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
"#,
    );
    for index in 1..=sheet_count {
        out.push_str(&format!(
            "<Override PartName=\"/xl/worksheets/sheet{index}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>\n"
        ));
    }
    out.push_str("</Types>\n");
    out
}

fn root_rels_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"#
}

fn workbook_xml(sheets: &[XlsxSheet]) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>
"#,
    );
    for (index, sheet) in sheets.iter().enumerate() {
        let sheet_id = index + 1;
        out.push_str(&format!(
            "<sheet name=\"{}\" sheetId=\"{sheet_id}\" r:id=\"rId{sheet_id}\"/>\n",
            xml_escape_attr(&sheet.name)
        ));
    }
    out.push_str("</sheets>\n</workbook>\n");
    out
}

fn workbook_rels_xml(sheet_count: usize) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
"#,
    );
    for index in 1..=sheet_count {
        out.push_str(&format!(
            "<Relationship Id=\"rId{index}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{index}.xml\"/>\n"
        ));
    }
    out.push_str("</Relationships>\n");
    out
}

fn worksheet_xml(sheet: &XlsxSheet) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
"#,
    );
    for (row_index, row) in sheet.rows.iter().enumerate() {
        let row_number = row_index + 1;
        out.push_str(&format!("<row r=\"{row_number}\">"));
        for (column_index, value) in row.iter().enumerate() {
            let cell_ref = format!("{}{}", column_name(column_index + 1), row_number);
            out.push_str(&format!("<c r=\"{cell_ref}\" t=\"inlineStr\"><is><t"));
            if preserves_space(value) {
                out.push_str(" xml:space=\"preserve\"");
            }
            out.push('>');
            out.push_str(&xml_escape_text(value));
            out.push_str("</t></is></c>");
        }
        out.push_str("</row>\n");
    }
    out.push_str("</sheetData>\n</worksheet>\n");
    out
}

fn column_name(mut index: usize) -> String {
    let mut name = String::new();
    while index > 0 {
        index -= 1;
        name.insert(0, (b'A' + (index % 26) as u8) as char);
        index /= 26;
    }
    name
}

fn preserves_space(value: &str) -> bool {
    value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace)
}

fn xml_escape_attr(value: &str) -> String {
    xml_escape(value, true)
}

fn xml_escape_text(value: &str) -> String {
    xml_escape(value, false)
}

fn xml_escape(value: &str, attr: bool) -> String {
    let mut out = String::new();
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\'' if attr => out.push_str("&apos;"),
            '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' => out.push(' '),
            _ => out.push(character),
        }
    }
    out
}

struct StoredZip {
    bytes: Vec<u8>,
    entries: Vec<StoredEntry>,
}

struct StoredEntry {
    name: String,
    crc32: u32,
    size: u32,
    local_offset: u32,
}

impl StoredZip {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn add(&mut self, name: &str, data: &[u8]) {
        let local_offset = u32_len(self.bytes.len());
        let name_bytes = name.as_bytes();
        let crc32 = crc32(data);
        let size = u32_len(data.len());

        write_u32(&mut self.bytes, 0x0403_4b50);
        write_u16(&mut self.bytes, 20);
        write_u16(&mut self.bytes, 0);
        write_u16(&mut self.bytes, 0);
        write_u16(&mut self.bytes, 0);
        write_u16(&mut self.bytes, 0);
        write_u32(&mut self.bytes, crc32);
        write_u32(&mut self.bytes, size);
        write_u32(&mut self.bytes, size);
        write_u16(&mut self.bytes, u16_len(name_bytes.len()));
        write_u16(&mut self.bytes, 0);
        self.bytes.extend_from_slice(name_bytes);
        self.bytes.extend_from_slice(data);

        self.entries.push(StoredEntry {
            name: name.to_string(),
            crc32,
            size,
            local_offset,
        });
    }

    fn finish(mut self) -> Vec<u8> {
        let central_start = u32_len(self.bytes.len());
        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            write_u32(&mut self.bytes, 0x0201_4b50);
            write_u16(&mut self.bytes, 20);
            write_u16(&mut self.bytes, 20);
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u32(&mut self.bytes, entry.crc32);
            write_u32(&mut self.bytes, entry.size);
            write_u32(&mut self.bytes, entry.size);
            write_u16(&mut self.bytes, u16_len(name_bytes.len()));
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u16(&mut self.bytes, 0);
            write_u32(&mut self.bytes, 0);
            write_u32(&mut self.bytes, entry.local_offset);
            self.bytes.extend_from_slice(name_bytes);
        }
        let central_size = u32_len(self.bytes.len() - central_start as usize);
        write_u32(&mut self.bytes, 0x0605_4b50);
        write_u16(&mut self.bytes, 0);
        write_u16(&mut self.bytes, 0);
        write_u16(&mut self.bytes, u16_len(self.entries.len()));
        write_u16(&mut self.bytes, u16_len(self.entries.len()));
        write_u32(&mut self.bytes, central_size);
        write_u32(&mut self.bytes, central_start);
        write_u16(&mut self.bytes, 0);
        self.bytes
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u16_len(value: usize) -> u16 {
    u16::try_from(value).expect("xlsx part count or name is too large")
}

fn u32_len(value: usize) -> u32 {
    u32::try_from(value).expect("xlsx workbook is too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workbook_is_a_zip_package() {
        let bytes = render_workbook(vec![XlsxSheet::new("Sheet", vec![row(["a", "b"])])]);
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(
            bytes
                .windows("xl/workbook.xml".len())
                .any(|window| window == b"xl/workbook.xml")
        );
    }
}
