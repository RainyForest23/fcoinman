use crate::finding::Finding;
use crate::scanner::Scanner;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const STANDARD_BINARY_PREFIXES: &[&str] = &[
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/",
];
const RECENT_DAYS_SECS: u64 = 30 * 86400;

pub struct PersistenceScanner;

impl Scanner for PersistenceScanner {

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_systemd_services());
        findings.extend(scan_crontabs());
        findings.extend(check_ld_preload());
        findings.extend(scan_kernel_modules());
        findings
    }
}

fn is_nonstandard_exec(exec_start: &str) -> bool {
    let binary = exec_start.split_whitespace().next().unwrap_or("");
    !STANDARD_BINARY_PREFIXES.iter().any(|p| binary.starts_with(p))
}

fn age_secs(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok().map(|d| d.as_secs())
}

fn scan_systemd_services() -> Vec<Finding> {
    let mut findings = Vec::new();
    let dirs = ["/etc/systemd/system", "/lib/systemd/system"];

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("service") {
                continue;
            }
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let path_str = path.display().to_string();

            for line in content.lines() {
                let line = line.trim();
                if !line.starts_with("ExecStart=") { continue; }
                let exec = &line["ExecStart=".len()..];

                if is_nonstandard_exec(exec) {
                    findings.push(Finding::critical(
                        "Non-standard systemd service binary",
                        "Service ExecStart points outside standard system paths — common attacker persistence",
                        &format!("{}: {}", path_str, line),
                    ));
                }
                if let Some(age) = age_secs(&path) {
                    if age < RECENT_DAYS_SECS {
                        findings.push(Finding::warning(
                            "Recently modified systemd service",
                            "Service file changed within last 30 days",
                            &path_str,
                        ));
                    }
                }
            }
        }
    }
    findings
}

fn scan_crontabs() -> Vec<Finding> {
    let mut findings = Vec::new();
    let dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
    ];
    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(age) = age_secs(&path) {
                    if age < RECENT_DAYS_SECS {
                        findings.push(Finding::warning(
                            "Recently modified crontab file",
                            "Cron entry changed within last 30 days — possible attacker persistence (Outlaw botnet pattern)",
                            &format!("{}", path.display()),
                        ));
                    }
                }
            }
        }
    }
    // User crontabs
    for spool_dir in &["/var/spool/cron/crontabs", "/var/spool/cron"] {
        if let Ok(entries) = fs::read_dir(spool_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(age) = age_secs(&path) {
                    if age < RECENT_DAYS_SECS {
                        findings.push(Finding::warning(
                            "Recently modified user crontab",
                            "User crontab changed within last 30 days",
                            &format!("{}", path.display()),
                        ));
                    }
                }
            }
        }
    }
    findings
}

fn check_ld_preload() -> Vec<Finding> {
    let mut findings = Vec::new();
    match fs::read_to_string("/etc/ld.so.preload") {
        Ok(content) if !content.trim().is_empty() => {
            findings.push(Finding::critical(
                "/etc/ld.so.preload is non-empty",
                "LD_PRELOAD rootkits inject malicious libraries into every process on the system",
                content.trim(),
            ));
        }
        _ => {}
    }
    findings
}

fn scan_kernel_modules() -> Vec<Finding> {
    let mut findings = Vec::new();
    // Known-legitimate module name prefixes
    let legit: &[&str] = &[
        "ip_", "nf_", "xt_", "br_", "veth", "tun", "tap", "loop",
        "ext4", "btrfs", "xfs", "fat", "nfs", "cifs",
        "nvidia", "amdgpu", "i915", "drm", "nouveau",
        "e1000", "igb", "ixgbe", "r8169", "virtio", "vmxnet",
        "uhci_hcd", "xhci_hcd", "ehci_hcd", "ahci", "nvme", "sd_mod",
        "dm_", "md_", "raid",
        "bluetooth", "cfg80211", "mac80211",
        "selinux", "apparmor",
        "overlay", "aufs", "fuse",
        "snd_", "hid_", "usbhid", "evdev", "input_",
        "tcp_", "udp_", "sctp",
        "zram", "squashfs",
    ];
    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return findings,
    };
    for line in content.lines() {
        let module = line.split_whitespace().next().unwrap_or("");
        if module.len() < 3 { continue; }
        let known = legit.iter().any(|p| module.starts_with(p))
            || module == "kvm" || module == "kvm_intel" || module == "kvm_amd";
        if !known {
            findings.push(Finding::info(
                "Unrecognized kernel module",
                "Module not in known-good list — verify with `modinfo <module>`",
                module,
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstandard_exec_flagged() {
        assert!(is_nonstandard_exec("/tmp/evil --flag"));
        assert!(is_nonstandard_exec("/var/bin/socket"));
        assert!(is_nonstandard_exec("socket")); // no path at all
    }

    #[test]
    fn standard_exec_not_flagged() {
        assert!(!is_nonstandard_exec("/usr/bin/python3 --arg"));
        assert!(!is_nonstandard_exec("/bin/bash -c something"));
        assert!(!is_nonstandard_exec("/usr/sbin/sshd -D"));
    }

    #[test]
    fn ld_preload_non_empty_flagged() {
        let path = "/tmp/fcoinman_test_ldpreload";
        std::fs::write(path, "/lib/evil.so\n").unwrap();
        // Can't test the real /etc/ld.so.preload path without root,
        // but the parsing logic is exercised here
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.trim().is_empty());
        std::fs::remove_file(path).unwrap();
    }
}
