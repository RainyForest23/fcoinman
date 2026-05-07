use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
}

impl Finding {
    pub fn critical(title: &str, description: &str, evidence: &str) -> Self {
        Self {
            severity: Severity::Critical,
            title: title.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
        }
    }

    pub fn warning(title: &str, description: &str, evidence: &str) -> Self {
        Self {
            severity: Severity::Warning,
            title: title.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
        }
    }

    pub fn info(title: &str, description: &str, evidence: &str) -> Self {
        Self {
            severity: Severity::Info,
            title: title.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_finding_has_correct_severity() {
        let f = Finding::critical("test", "desc", "evidence");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.title, "test");
        assert_eq!(f.evidence, "evidence");
    }

    #[test]
    fn warning_finding_has_correct_severity() {
        let f = Finding::warning("test", "desc", "ev");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn info_finding_has_correct_severity() {
        let f = Finding::info("test", "desc", "ev");
        assert_eq!(f.severity, Severity::Info);
    }
}
