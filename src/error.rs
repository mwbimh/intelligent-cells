use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub outcome_unknown: bool,
}
pub type Result<T> = std::result::Result<T, IcError>;
impl IcError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            outcome_unknown: false,
        }
    }
    pub fn unknown(mut self) -> Self {
        self.outcome_unknown = true;
        self
    }
}
impl std::fmt::Display for IcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for IcError {}
impl From<std::io::Error> for IcError {
    fn from(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::NotFound => "ENOENT",
            std::io::ErrorKind::PermissionDenied => "EACCES",
            std::io::ErrorKind::AlreadyExists => "EEXIST",
            _ => "IO_ERROR",
        };
        Self::new(code, error.to_string())
    }
}
impl From<serde_json::Error> for IcError {
    fn from(error: serde_json::Error) -> Self {
        Self::new("INVALID_JSON", error.to_string())
    }
}
