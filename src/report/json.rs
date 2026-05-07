use crate::finding::{Finding, Severity};
use serde::Serialize;

#[derive(Serialize)]
pub struct ScanReport<'a> {
    pub verdict: &'static str,
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

    let report = ScanReport {
        verdict,
        findings,
        summary: Summary { critical, warning, info },
    };

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
