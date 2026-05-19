use crate::finding::Finding;
use crate::scanner::Scanner;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct LogScanner;

impl Scanner for LogScanner {

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

    let brute_force_ips: Vec<(&String, &u32)> = failed_by_ip.iter()
        .filter(|(_, count)| **count > 20)
        .collect();

    if !brute_force_ips.is_empty() {
        let total_attempts: u32 = brute_force_ips.iter().map(|(_, c)| **c).sum();
        let top = {
            let mut sorted = brute_force_ips.clone();
            sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
            sorted.iter().take(3)
                .map(|(ip, c)| format!("{} ({}x)", ip, c))
                .collect::<Vec<_>>()
                .join(", ")
        };
        findings.push(Finding::warning(
            "SSH brute force attacks detected",
            "Multiple IPs made many failed login attempts — all blocked, not a confirmed breach. Use fail2ban to reduce noise.",
            &format!("{} IPs, {} total attempts (source: {}). Top offenders: {}",
                brute_force_ips.len(), total_attempts, source, top),
        ));
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

// ── Summary ──────────────────────────────────────────────────────────────────

pub fn print_summary() {
    println!("\n[ATTACK SUMMARY] SSH brute force analysis\n");

    // (count, first_ts, last_ts) — process auth.log.1 first (older), then auth.log (newer)
    let mut agg: HashMap<String, (u32, String, String)> = HashMap::new();
    let mut total_lines = 0usize;
    let mut found_files: Vec<&str> = Vec::new();

    for path in &["/var/log/auth.log.1", "/var/log/auth.log"] {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        total_lines += content.lines().count();
        found_files.push(path);
        for line in content.lines() {
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(ip) = extract_ip(line) {
                    let ts = extract_timestamp(line);
                    let e = agg.entry(ip).or_insert((0, ts.clone(), ts.clone()));
                    e.0 += 1;
                    e.2 = ts; // last seen — lines are chronological, overwrite each time
                }
            }
        }
    }

    if agg.is_empty() {
        println!("  No auth logs found or no failed attempts recorded.");
        return;
    }

    let mut rows: Vec<(String, u32, String, String)> = agg
        .into_iter()
        .filter(|(_, (c, _, _))| *c > 20)
        .map(|(ip, (c, f, l))| (ip, c, f, l))
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));

    let total_attempts: u32 = rows.iter().map(|(_, c, _, _)| c).sum();

    println!("  Log files : {}", found_files.join(" + "));
    println!("  Lines     : {}", fmt_num(total_lines as u32));
    println!("  Period    : {} ~ {}", rows.iter().map(|r| r.2.clone()).min().unwrap_or_default(),
                                       rows.iter().map(|r| r.3.clone()).max().unwrap_or_default());
    println!("  Attackers : {} unique IPs  |  Total attempts: {} (all blocked)\n",
        fmt_num(rows.len() as u32), fmt_num(total_attempts));

    // Subnet clusters (/24)
    let mut subnets: HashMap<String, (u32, u32)> = HashMap::new(); // prefix → (ip_count, attempt_count)
    for (ip, count, _, _) in &rows {
        let prefix = ip.rsplit_once('.').map(|x| x.0).unwrap_or("").to_string();
        let e = subnets.entry(prefix).or_insert((0, 0));
        e.0 += 1;
        e.1 += count;
    }
    let mut clusters: Vec<(String, u32, u32)> = subnets
        .into_iter()
        .filter(|(_, (ip_cnt, _))| *ip_cnt >= 3)
        .map(|(p, (ic, ac))| (p, ic, ac))
        .collect();
    clusters.sort_by_key(|c| std::cmp::Reverse(c.2));
    if !clusters.is_empty() {
        println!("  [!] Coordinated subnet attacks detected:");
        for (prefix, ip_cnt, att_cnt) in &clusters {
            println!("      {}.0/24 — {} IPs, {} attempts (likely botnet)",
                prefix, ip_cnt, fmt_num(*att_cnt));
        }
        println!();
    }

    // Table header
    let geo_available = std::process::Command::new("which").arg("whois").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if geo_available {
        println!("  {:<4}  {:>9}  {:<16}  {:<34}  {:<6}  Org",
            "Rank", "Attempts", "IP", "Period", "CC");
        println!("  {}  {}  {}  {}  {}  {}",
            "─".repeat(4), "─".repeat(9), "─".repeat(16), "─".repeat(34), "─".repeat(6), "─".repeat(24));
    } else {
        println!("  {:<4}  {:>9}  {:<16}  Period",
            "Rank", "Attempts", "IP");
        println!("  {}  {}  {}  {}",
            "─".repeat(4), "─".repeat(9), "─".repeat(16), "─".repeat(34));
    }

    for (rank, (ip, count, first, last)) in rows.iter().take(20).enumerate() {
        let period = format!("{} ~ {}", first, last);
        if geo_available && rank < 15 {
            let (cc, org) = whois_lookup(ip);
            println!("  {:>4}  {:>9}  {:<16}  {:<34}  {:<6}  {}",
                rank + 1, fmt_num(*count), ip, period, cc, org);
        } else if geo_available {
            println!("  {:>4}  {:>9}  {:<16}  {:<34}  {:<6}  -",
                rank + 1, fmt_num(*count), ip, period, "-");
        } else {
            println!("  {:>4}  {:>9}  {:<16}  {}",
                rank + 1, fmt_num(*count), ip, period);
        }
    }

    if rows.len() > 20 {
        println!("  ... and {} more (all blocked)", rows.len() - 20);
    }
    println!();
}

fn fmt_num(n: u32) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { result.push(','); }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn whois_lookup(ip: &str) -> (String, String) {
    // Use `timeout 5` to avoid hanging on slow whois servers
    let output = std::process::Command::new("timeout")
        .args(["5", "whois", ip])
        .output();
    let text = match output {
        Ok(o) if o.status.success() || !o.stdout.is_empty() =>
            String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return ("-".to_string(), "-".to_string()),
    };
    let cc = text.lines()
        .find(|l| l.to_lowercase().starts_with("country:"))
        .and_then(|l| l.split_once(':').map(|x| x.1.trim().to_string()))
        .unwrap_or_else(|| "-".to_string());
    let org = text.lines()
        .find(|l| {
            let lo = l.to_lowercase();
            lo.starts_with("netname:") || lo.starts_with("orgname:") || lo.starts_with("org-name:")
        })
        .and_then(|l| l.split_once(':').map(|x| x.1.trim().to_string()))
        .map(|val| if val.len() > 24 { val[..24].to_string() } else { val })
        .unwrap_or_else(|| "-".to_string());
    (cc, org)
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

        // (count, first_timestamp, last_timestamp)
        let mut failed: HashMap<String, (u32, String, String)> = HashMap::new();
        let mut events: Vec<String> = Vec::new();

        for line in content.lines() {
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(ip) = extract_ip(line) {
                    let ts = extract_timestamp(line);
                    let entry = failed.entry(ip).or_insert((0, ts.clone(), ts.clone()));
                    entry.0 += 1;
                    entry.2 = ts; // last seen — lines are in chronological order
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

        for (ip, (count, first, last)) in &failed {
            if *count > 20 {
                events.push(format!(
                    "  [BRUTE FORCE] {} — {} attempts  ({} ~ {})",
                    ip, count, first, last
                ));
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
        let bf = findings.iter().find(|f| f.title.contains("brute force")).unwrap();
        assert!(matches!(bf.severity, crate::finding::Severity::Warning));
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
