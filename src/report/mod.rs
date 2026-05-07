pub mod json;

use crate::finding::{Finding, Severity};
use colored::Colorize;

pub fn print_findings(findings: &[Finding], scanner_count: usize) {
    println!("\nRunning {} scanners...\n", scanner_count);

    if findings.is_empty() {
        println!("{}", "No issues found. System appears clean.".green().bold());
        return;
    }

    for f in findings {
        let label = match f.severity {
            Severity::Critical => "[CRITICAL]".red().bold(),
            Severity::Warning  => "[WARNING] ".yellow().bold(),
            Severity::Info     => "[INFO]    ".cyan(),
        };
        println!("{} {}", label, f.title.bold());
        println!("           {}", f.description.dimmed());
        println!("           Evidence: {}", f.evidence);
        println!();
    }

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warnings  = findings.iter().filter(|f| f.severity == Severity::Warning).count();

    println!("{}", "─".repeat(55));

    if critical > 0 {
        println!(
            "Result: {}",
            format!("LIKELY COMPROMISED  ({} critical, {} warnings)", critical, warnings)
                .red().bold()
        );
        println!();
        println!("{}", "  Recommendation: Disconnect from network immediately.".red().bold());
        println!("{}", "  Do not trust this system. Consider forensic imaging before format.".red());
        println!("{}", "  Run `sudo fcoinman logs` for a full attack timeline.".red());
    } else if warnings > 0 {
        println!(
            "Result: {}",
            format!("SUSPICIOUS  ({} warnings) — manual review recommended", warnings)
                .yellow().bold()
        );
    } else {
        println!("Result: {}", "CLEAN".green().bold());
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn print_does_not_panic_on_empty() {
        print_findings(&[], 5);
    }

    #[test]
    fn print_does_not_panic_with_all_severities() {
        let findings = vec![
            Finding::critical("critical title", "desc", "evidence"),
            Finding::warning("warning title", "desc", "evidence"),
            Finding::info("info title", "desc", "evidence"),
        ];
        print_findings(&findings, 7);
    }
}
