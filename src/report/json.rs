use crate::finding::{Finding, Severity};
use serde::Serialize;

#[derive(Serialize)]
pub struct ScanReport<'a> {
    pub verdict: &'static str,
    pub scanned_at: String,
    pub hostname: String,
    pub findings: &'a [Finding],
    pub summary: Summary,
}

#[derive(Serialize)]
pub struct Summary {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

pub fn print_json(findings: &[Finding]) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warning  = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let info     = findings.iter().filter(|f| f.severity == Severity::Info).count();

    let verdict = if critical > 0 {
        "LIKELY_COMPROMISED"
    } else if warning > 0 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    };

    let scanned_at = chrono::Utc::now().to_rfc3339();
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();

    let report = ScanReport {
        verdict,
        scanned_at,
        hostname,
        findings,
        summary: Summary { critical, warning, info },
    };

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
