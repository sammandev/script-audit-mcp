#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowKind {
    Test,
    Init,
    Final,
}

impl FlowKind {
    pub fn from_text(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "TEST" => Some(Self::Test),
            "INIT" => Some(Self::Init),
            "FINAL" => Some(Self::Final),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Test => "TEST",
            Self::Init => "INIT",
            Self::Final => "FINAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowRow {
    pub key: String,
    pub item: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub header: String,
    pub kind: FlowKind,
    pub station: String,
    pub sku: Option<String>,
    pub line: usize,
    pub items: Vec<String>,
    pub rows: Vec<FlowRow>,
}

#[derive(Debug, Clone)]
pub struct ScriptSection {
    pub name: String,
    pub display_name: String,
    pub header: String,
    pub error_code: Option<String>,
    pub retry: Option<u32>,
    pub source: String,
    pub line: usize,
    pub data_entries: Vec<DataEntry>,
    pub rows: Vec<ScriptRow>,
}

#[derive(Debug, Clone)]
pub struct DataEntry {
    pub key: String,
    pub value: String,
    pub line: usize,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct DataSection {
    pub source: String,
    pub name: String,
    pub display_name: String,
    pub header: String,
    pub line: usize,
    pub entries: Vec<DataEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct ScriptInfo {
    pub script_version: Option<String>,
    pub program_version: Option<String>,
    pub ver: Option<String>,
    pub model_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VariableReference {
    pub source: String,
    pub line: usize,
    pub row_label: String,
    pub token: String,
    pub header: String,
    pub key: Option<String>,
    pub kind: String,
    pub status: String,
    pub resolved_value: Option<String>,
    pub value_source: Option<String>,
    pub value_line: Option<usize>,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct ItemHeaderContext {
    pub source: String,
    pub line: usize,
    pub header: String,
    pub item_name: String,
    pub error_code: Option<String>,
    pub retry: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DllInvocationContext {
    pub source: String,
    pub line: usize,
    pub item_name: String,
    pub row_label: String,
    pub dll_name: String,
    pub dll_base_name: String,
    pub dll_suffixes: Vec<String>,
    pub dll_invocation_mode: String,
    pub dll_function: String,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct ScriptRow {
    pub label: String,
    pub label_raw: String,
    pub retry: Option<u32>,
    pub line: usize,
    pub raw: String,
    pub raw_value: String,
    pub dll_name: String,
    pub dll_base_name: String,
    pub dll_suffixes: Vec<String>,
    pub dll_invocation_mode: String,
    pub dll_function: String,
    pub criteria: String,
    pub parameters: String,
    pub timeout: String,
    pub pass_path: String,
    pub fail_path: String,
    pub error_code: Option<String>,
    pub extra_fields: Vec<String>,
    pub unterminated_quote: bool,
}
