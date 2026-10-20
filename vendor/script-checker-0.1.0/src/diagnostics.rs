use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelatedLocation {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub evidence: String,
    pub related: Vec<RelatedLocation>,
}

impl Diagnostic {
    pub fn new(
        severity: Severity,
        code: impl Into<String>,
        file: impl Into<String>,
        line: usize,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            file: file.into(),
            line,
            message: message.into(),
            evidence: evidence.into(),
            related: Vec::new(),
        }
    }

    pub fn with_related(mut self, file: impl Into<String>, line: usize) -> Self {
        self.related.push(RelatedLocation {
            file: file.into(),
            line,
        });
        self
    }
}

pub fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| path.display().to_string())
}
