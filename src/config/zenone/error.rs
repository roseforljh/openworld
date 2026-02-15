use std::fmt;

/// ZenOne 告警/错误等级
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for DiagLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiagLevel::Info => write!(f, "INFO"),
            DiagLevel::Warn => write!(f, "WARN"),
            DiagLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// 标准错误码（稳定 API，不可随意变更）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagCode {
    InvalidSchemaVersion,
    MissingRequiredField,
    InvalidFieldType,
    UnknownField,
    DuplicateName,
    UnresolvedReference,
    InvalidPortRange,
    InvalidUriFormat,
    FieldDropped,
    ValueInferred,
    SignatureInvalid,
    SignatureExpired,
    ReplayDetected,
    MergeConflict,
    UnsupportedProtocol,
    CircularReference,
    NodeSkipped,
}

impl DiagCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiagCode::InvalidSchemaVersion => "INVALID_SCHEMA_VERSION",
            DiagCode::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            DiagCode::InvalidFieldType => "INVALID_FIELD_TYPE",
            DiagCode::UnknownField => "UNKNOWN_FIELD",
            DiagCode::DuplicateName => "DUPLICATE_NAME",
            DiagCode::UnresolvedReference => "UNRESOLVED_REFERENCE",
            DiagCode::InvalidPortRange => "INVALID_PORT_RANGE",
            DiagCode::InvalidUriFormat => "INVALID_URI_FORMAT",
            DiagCode::FieldDropped => "FIELD_DROPPED",
            DiagCode::ValueInferred => "VALUE_INFERRED",
            DiagCode::SignatureInvalid => "SIGNATURE_INVALID",
            DiagCode::SignatureExpired => "SIGNATURE_EXPIRED",
            DiagCode::ReplayDetected => "REPLAY_DETECTED",
            DiagCode::MergeConflict => "MERGE_CONFLICT",
            DiagCode::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL",
            DiagCode::CircularReference => "CIRCULAR_REFERENCE",
            DiagCode::NodeSkipped => "NODE_SKIPPED",
        }
    }

    pub fn default_level(&self) -> DiagLevel {
        match self {
            DiagCode::ValueInferred => DiagLevel::Info,
            DiagCode::FieldDropped | DiagCode::NodeSkipped | DiagCode::UnknownField => {
                DiagLevel::Warn
            }
            _ => DiagLevel::Error,
        }
    }
}

impl fmt::Display for DiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 单条诊断信息
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub level: DiagLevel,
    pub code: DiagCode,
    pub path: String,
    pub message: String,
    pub hint: Option<String>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} at {}: {}",
            self.level, self.code, self.path, self.message
        )?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {})", hint)?;
        }
        Ok(())
    }
}

/// 诊断收集器
#[derive(Debug, Clone, Default)]
pub struct Diagnostics {
    pub items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn push(&mut self, diag: Diagnostic) {
        self.items.push(diag);
    }

    pub fn error(&mut self, code: DiagCode, path: impl Into<String>, message: impl Into<String>) {
        self.items.push(Diagnostic {
            level: DiagLevel::Error,
            code,
            path: path.into(),
            message: message.into(),
            hint: None,
        });
    }

    pub fn warn(&mut self, code: DiagCode, path: impl Into<String>, message: impl Into<String>) {
        self.items.push(Diagnostic {
            level: DiagLevel::Warn,
            code,
            path: path.into(),
            message: message.into(),
            hint: None,
        });
    }

    pub fn info(&mut self, code: DiagCode, path: impl Into<String>, message: impl Into<String>) {
        self.items.push(Diagnostic {
            level: DiagLevel::Info,
            code,
            path: path.into(),
            message: message.into(),
            hint: None,
        });
    }

    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.level == DiagLevel::Error)
    }

    pub fn errors(&self) -> Vec<&Diagnostic> {
        self.items
            .iter()
            .filter(|d| d.level == DiagLevel::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.items
            .iter()
            .filter(|d| d.level == DiagLevel::Warn)
            .collect()
    }

    pub fn merge(&mut self, other: Diagnostics) {
        self.items.extend(other.items);
    }
}
