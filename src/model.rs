use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Function {
    pub source: String,
    pub interface: String,
    pub name: String,
    pub description: String,
    pub convention: Option<i64>,
    pub category: String,
    pub execution_role: String,
    pub execution_phase: String,
    pub composition_supported: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Snapshot {
    pub functions: Vec<Function>,
    pub parameter_definitions: Vec<Definition>,
    pub criteria_definitions: Vec<Definition>,
    pub parameter_links: Vec<Link>,
    pub criteria_links: Vec<Link>,
    pub examples: Vec<Example>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Definition {
    pub name: String,
    pub device_name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub unit: String,
    pub default_value: Option<String>,
    pub allowed_values: String,
    pub cardinality: String,
    pub value_pattern: String,
    pub required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Link {
    pub name: String,
    pub function_source: String,
    pub function_name: String,
    pub device_name: String,
    pub position: Option<i64>,
    pub required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct Example {
    pub function_source: String,
    pub device_name: String,
    pub function_name: String,
    pub script: String,
    pub meaning: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Field {
    pub name: String,
    pub device_name: String,
    pub position: Option<i64>,
    pub required: bool,
    pub definition: Option<Definition>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionSchema {
    pub function: Function,
    pub device_scope: String,
    pub parameters: Vec<Field>,
    pub criteria: Vec<Field>,
    pub examples: Vec<Example>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct CriteriaSuggestions {
    pub criteria: Vec<Field>,
    pub examples: Vec<Example>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum Value {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum CriteriaInput {
    Raw(String),
    Named(BTreeMap<String, Value>),
}

impl Default for CriteriaInput {
    fn default() -> Self {
        Self::Named(BTreeMap::new())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComposeRequest {
    pub device: String,
    pub function: String,
    #[serde(default)]
    pub device_scope: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    #[serde(default)]
    pub criteria: CriteriaInput,
    pub timeout: u64,
    #[serde(default)]
    pub pass_path: Option<String>,
    #[serde(default)]
    pub fail_path: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
    Incomplete,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Diagnostic {
    pub field: String,
    pub code: String,
    pub message: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ComposeResult {
    pub line: String,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Incomplete,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ValidationReport {
    pub status: ValidationStatus,
    pub segments: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}
