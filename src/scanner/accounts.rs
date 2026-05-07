use crate::finding::Finding;
use crate::scanner::Scanner;
use std::fs;

pub struct AccountScanner;

impl Scanner for AccountScanner {

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_passwd_backdoors("/etc/passwd"));
        findings.extend(check_authorized_keys());
        findings
    }
}

fn check_passwd_backdoors(path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 {
            let username = parts[0];
            let uid = parts[2];
            if uid == "0" && username != "root" {
                findings.push(Finding::critical(
                    "UID-0 backdoor account detected",
                    "Non-root account with UID 0 grants full root privileges without the root username",
                    line,
                ));
            }
        }
    }
    findings
}

fn check_authorized_keys() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Always check root's keys
    findings.extend(check_key_file("/root/.ssh/authorized_keys"));

    // Check all users' home directories via /etc/passwd
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let home = parts[5];
                let key_path = format!("{}/.ssh/authorized_keys", home);
                if key_path != "/root/.ssh/authorized_keys" {
                    findings.extend(check_key_file(&key_path));
                }
            }
        }
    }
    findings
}

fn check_key_file(path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.contains("root@root") || line.ends_with("@root") {
            findings.push(Finding::warning(
                "Suspicious SSH authorized key",
                "Key comment suggests attacker-planted backdoor (root@root pattern)",
                &format!("{}: ...{}", path, &line[line.len().saturating_sub(40)..]),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_uid0_backdoor() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nsystem:x:0:1001::/root:/bin/bash\n";
        let path = "/tmp/fcoinman_test_passwd";
        std::fs::write(path, passwd).unwrap();
        let findings = check_passwd_backdoors(path);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("system"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ignores_legitimate_root_entry() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n";
        let path = "/tmp/fcoinman_test_passwd2";
        std::fs::write(path, passwd).unwrap();
        let findings = check_passwd_backdoors(path);
        assert_eq!(findings.len(), 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_passwd_returns_empty() {
        let findings = check_passwd_backdoors("/nonexistent/path");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_root_at_root_key() {
        let keys = "ssh-rsa AAAAB3NzaC1... root@root\n";
        let path = "/tmp/fcoinman_test_keys";
        std::fs::write(path, keys).unwrap();
        let findings = check_key_file(path);
        assert_eq!(findings.len(), 1);
        std::fs::remove_file(path).unwrap();
    }
}
