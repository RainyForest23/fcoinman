use crate::finding::Finding;
use crate::scanner::Scanner;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct LogScanner;

impl Scanner for LogScanner {
    fn name(&self) -> &str { "Log & Timeline Scanner" }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_cleared_logs());
        findings.extend(scan_auth_logs());
        findings
    }
}

fn check_cleared_logs() -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in &["/var/log/auth.log", "/var/log/syslog"] {
        let p = Path::new(path);
        if !p.exists() { continue; }
        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(1);
        if size == 0 {
            findings.push(Finding::critical(
                "Critical log file is empty — possible evidence destruction",
                "Attackers wipe auth.log to erase SSH brute force and login records",
                path,
            ));
        }
    }
    findings
}

fn scan_auth_logs() -> Vec<Finding> {
    let mut findings = Vec::new();
    for path in &["/var/log/auth.log", "/var/log/auth.log.1"] {
        if let Ok(content) = fs::read_to_string(path) {
            findings.extend(parse_auth_log(&content, path));
        }
    }
    findings
}

pub fn parse_auth_log(content: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut failed_by_ip: HashMap<String, u32> = HashMap::new();
    let mut successful_logins: Vec<String> = Vec::new();

    for line in content.lines() {
        if line.contains("Failed password") || line.contains("Invalid user") {
            if let Some(ip) = extract_ip(line) {
                *failed_by_ip.entry(ip).or_insert(0) += 1;
            }
        }
        if line.contains("Accepted password") || line.contains("Accepted publickey") {
            if let Some(ip) = extract_ip(line) {
                let ts = extract_timestamp(line);
                successful_logins.push(format!("{} from {}", ts, ip));
            }
        }
    }

    for (ip, count) in &failed_by_ip {
        if *count > 20 {
            findings.push(Finding::critical(
                "SSH brute force attack detected",
                "Single IP made many failed login attempts in a short window",
                &format!("IP: {}  —  {} failed attempts  (source: {})", ip, count, source),
            ));
        }
    }

    if !successful_logins.is_empty() {
        findings.push(Finding::info(
            "Successful SSH logins recorded",
            "Review these logins — confirm each is authorized",
            &successful_logins.join(" | "),
        ));
    }

    findings
}

pub fn print_timeline() {
    println!("\n[LOG ANALYSIS] Reconstructing attack timeline...\n");

    for path in &["/var/log/auth.log", "/var/log/auth.log.1"] {
        let p = Path::new(path);
        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);

        if size == 0 {
            println!("  ⚠️  {} is EMPTY — log was cleared (evidence destruction)", path);
            continue;
        }

        let content = match fs::read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue,
        };

        println!(
            "  Reading {} ({} bytes, {} lines)\n",
            path,
            size,
            content.lines().count()
        );

        let mut failed: HashMap<String, u32> = HashMap::new();
        let mut events: Vec<String> = Vec::new();

        for line in content.lines() {
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(ip) = extract_ip(line) {
                    *failed.entry(ip).or_insert(0) += 1;
                }
            }
            if line.contains("Accepted password") || line.contains("Accepted publickey") {
                events.push(format!("  [SSH LOGIN]   {}", &line[..line.len().min(100)]));
            }
            if line.contains("new user") || line.contains("useradd") {
                events.push(format!("  [NEW ACCOUNT] {}", &line[..line.len().min(100)]));
            }
            if line.contains("systemctl") && (line.contains("enable") || line.contains("start")) {
                events.push(format!("  [SERVICE]     {}", &line[..line.len().min(100)]));
            }
        }

        for (ip, count) in &failed {
            if *count > 20 {
                events.push(format!("  [BRUTE FORCE] {} — {} failed SSH attempts", ip, count));
            }
        }

        events.sort();
        for e in &events {
            println!("{}", e);
        }

        if events.is_empty() {
            println!("  (no notable events found in this log)");
        }
        println!();
    }
}

fn extract_ip(line: &str) -> Option<String> {
    let idx = line.rfind("from ")?;
    let ip: String = line[idx + 5..].split_whitespace().next()?.to_string();
    if ip.chars().all(|c| c.is_ascii_digit() || c == '.') && ip.contains('.') {
        Some(ip)
    } else {
        None
    }
}

fn extract_timestamp(line: &str) -> String {
    line.splitn(4, ' ').take(3).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brute_force_detected() {
        let mut log = String::new();
        for _ in 0..25 {
            log.push_str(
                "Mar 28 03:14:22 srv sshd[1]: Failed password for root from 45.33.32.156 port 54321 ssh2\n",
            );
        }
        let findings = parse_auth_log(&log, "test");
        assert!(findings.iter().any(|f| f.title.contains("brute force")));
    }

    #[test]
    fn low_failure_count_not_flagged() {
        let mut log = String::new();
        for _ in 0..5 {
            log.push_str(
                "Mar 28 03:14:22 srv sshd[1]: Failed password for root from 1.2.3.4 port 123 ssh2\n",
            );
        }
        let findings = parse_auth_log(&log, "test");
        assert!(!findings.iter().any(|f| f.title.contains("brute force")));
    }

    #[test]
    fn ip_extracted_from_failed_line() {
        let line = "Mar 28 03:14 srv sshd[1]: Failed password for root from 45.33.32.156 port 54321 ssh2";
        assert_eq!(extract_ip(line), Some("45.33.32.156".to_string()));
    }

    #[test]
    fn successful_login_recorded() {
        let log = "Mar 28 03:19 srv sshd[1]: Accepted password for root from 45.33.32.156 port 54321 ssh2\n";
        let findings = parse_auth_log(&log, "test");
        assert!(findings.iter().any(|f| f.title.contains("Successful SSH")));
    }

    #[test]
    fn ip_not_extracted_from_unrelated_line() {
        let line = "Mar 28 03:14 srv sudo: joe : TTY=pts/0 ; PWD=/home/joe";
        assert_eq!(extract_ip(line), None);
    }
}
