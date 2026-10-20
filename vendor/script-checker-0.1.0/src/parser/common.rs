use crate::models::FlowKind;

pub const TERMINAL_TOKENS: &[&str] = &["QUIT", "FAIL", "PASS", "END"];

#[derive(Debug, Clone)]
pub struct FlowSectionParts {
    pub kind: FlowKind,
    pub station: String,
    pub sku: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SectionNameParts {
    pub name: String,
    pub error_code: Option<String>,
    pub retry: Option<u32>,
}

pub fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(';') || trimmed.starts_with("//")
}

pub fn is_ignored_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || is_comment(line)
        || trimmed.to_ascii_lowercase().starts_with("checksumed:")
}

pub fn case_key(value: &str) -> String {
    value.trim().to_lowercase()
}

pub fn parse_flow_section(line: &str) -> Option<FlowSectionParts> {
    let inner = bracket_inner(line)?;
    let colon = inner.find(':')?;
    let kind_text = inner[..colon]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let kind = match kind_text.to_ascii_uppercase().as_str() {
        "TEST FLOW" => FlowKind::Test,
        "INIT FLOW" => FlowKind::Init,
        "FINAL FLOW" => FlowKind::Final,
        _ => return None,
    };
    let rest = inner[colon + 1..].trim();
    let sku_pos = find_ascii_case_insensitive(rest, "#SKU:");
    let (station, sku) = match sku_pos {
        Some(index) => (
            rest[..index].trim().to_string(),
            Some(rest[index + "#SKU:".len()..].trim().to_string())
                .filter(|value| !value.is_empty()),
        ),
        None => (rest.trim().to_string(), None),
    };
    Some(FlowSectionParts { kind, station, sku })
}

pub fn invalid_flow_section_kind(line: &str) -> Option<String> {
    let inner = bracket_inner(line)?;
    let colon = inner.find(':')?;
    let kind_text = inner[..colon]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let upper = kind_text.to_ascii_uppercase();
    if matches!(upper.as_str(), "INIT FLOW" | "TEST FLOW" | "FINAL FLOW") {
        return None;
    }
    if looks_like_flow_kind(&upper) {
        return Some(kind_text);
    }
    None
}

pub fn parse_any_section(line: &str) -> Option<String> {
    bracket_inner(line).map(str::to_string)
}

pub fn parse_flow_row(line: &str) -> Option<(String, String)> {
    let (key, value) = split_assignment(line)?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    let value = value.trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return None;
    }
    Some((key.to_string(), value[1..value.len() - 1].to_string()))
}

pub fn parse_script_row(line: &str) -> Option<(String, String, bool)> {
    let (label, value) = split_assignment(line)?;
    let label = label.trim();
    if label.is_empty() || label.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }
    let value = value.trim();
    if !value.starts_with('"') {
        return None;
    }
    if value.len() >= 2 && value.ends_with('"') {
        return Some((
            label.to_string(),
            value[1..value.len() - 1].to_string(),
            false,
        ));
    }
    let recovered = &value[1..];
    if recovered.contains('"') {
        return None;
    }
    Some((label.to_string(), recovered.trim_end().to_string(), true))
}

pub fn parse_data_assignment(line: &str) -> Option<(String, String)> {
    let (key, value) = split_assignment(line)?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    let value = value.trim();
    let value = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    Some((key.to_string(), value.to_string()))
}

pub fn flow_header(kind: &FlowKind, station: &str, sku: Option<&str>) -> String {
    match sku.filter(|value| !value.trim().is_empty()) {
        Some(sku) => format!(
            "[{} FLOW:{}#SKU:{}]",
            kind.as_str(),
            station.trim(),
            sku.trim()
        ),
        None => format!("[{} FLOW:{}]", kind.as_str(), station.trim()),
    }
}

pub fn canonical_header(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_lowercase()
}

pub fn section_name(header: &str) -> (String, Option<u32>) {
    let parts = section_name_parts(header);
    (parts.name, parts.retry)
}

pub fn section_name_parts(header: &str) -> SectionNameParts {
    let text = header.trim();
    let Some((name, suffix)) = text.split_once('#') else {
        return SectionNameParts {
            name: text.to_string(),
            error_code: None,
            retry: None,
        };
    };
    let Some((error_code, retry)) = parse_item_header_suffix(suffix) else {
        return SectionNameParts {
            name: text.to_string(),
            error_code: None,
            retry: None,
        };
    };
    SectionNameParts {
        name: name.trim().to_string(),
        error_code,
        retry,
    }
}

pub fn split_retry_label(label: &str) -> (String, Option<u32>) {
    let text = label.trim();
    let lower = text.to_ascii_lowercase();
    if let Some(index) = lower.rfind("#retry:") {
        let digits = &text[index + "#Retry:".len()..];
        if !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit()) {
            return (text[..index].trim().to_string(), digits.parse::<u32>().ok());
        }
    }
    (text.to_string(), None)
}

pub fn label_without_retry(label: &str) -> String {
    split_retry_label(label).0
}

pub fn is_terminal_token(value: &str) -> bool {
    let upper = value.trim().to_ascii_uppercase();
    TERMINAL_TOKENS.iter().any(|token| *token == upper)
}

pub fn is_error_code_format(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(colon) = trimmed.find(':') else {
        return false;
    };
    trimmed[..colon].trim().eq_ignore_ascii_case("ERRCODE")
        && !trimmed[colon + 1..].trim().is_empty()
}

fn bracket_inner(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.len() < 2 || !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    Some(trimmed[1..trimmed.len() - 1].trim())
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let index = line.find('=')?;
    Some((&line[..index], &line[index + 1..]))
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn looks_like_flow_kind(value: &str) -> bool {
    value.contains("FLOW")
        || matches!(value, "INIT" | "TEST" | "FINAL")
        || edit_distance(value, "INIT FLOW") <= 2
        || edit_distance(value, "TEST FLOW") <= 2
        || edit_distance(value, "FINAL FLOW") <= 2
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left_chars: Vec<char> = left.chars().collect();
    let right_chars: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right_chars.len()).collect();
    let mut current = vec![0; right_chars.len() + 1];
    for (left_index, left_char) in left_chars.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let substitution = usize::from(left_char != right_char);
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + substitution);
        }
        previous.clone_from(&current);
    }
    previous[right_chars.len()]
}

fn parse_item_header_suffix(suffix: &str) -> Option<(Option<String>, Option<u32>)> {
    let mut error_code = None;
    let mut retry = None;
    let mut recognized = false;
    for part in suffix.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed.split_once(':')?;
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("ErrCode") {
            recognized = true;
            if !value.is_empty() {
                error_code = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("Retry") {
            recognized = true;
            if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) {
                retry = value.parse::<u32>().ok();
            }
        } else {
            return None;
        }
    }
    recognized.then_some((error_code, retry))
}
