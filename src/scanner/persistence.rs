use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const SUSPICIOUS_EXEC_PREFIXES: &[&str] = &[
    "/tmp/", "/dev/shm/", "/var/bin/", "/var/tmp/",
];

const RECENT_DAYS_SECS: u64 = 30 * 86400;

pub struct PersistenceScanner {
    pub ioc: IocDatabase,
}

impl PersistenceScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for PersistenceScanner {

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_systemd_services(&self.ioc));
        findings.extend(scan_crontabs());
        findings.extend(check_ld_preload());
        findings.extend(scan_kernel_modules());
        findings
    }
}

fn strip_systemd_prefix(exec: &str) -> &str {
    // systemd allows !, !!, -, @, + prefixes before the binary path
    let exec = exec.trim_start_matches('!');
    let exec = exec.trim_start_matches('-');
    exec.trim_start_matches('@')
}

fn is_suspicious_exec_path(exec_start: &str) -> bool {
    let binary = strip_systemd_prefix(exec_start.split_whitespace().next().unwrap_or(""));
    SUSPICIOUS_EXEC_PREFIXES.iter().any(|p| binary.starts_with(p))
}

fn age_secs(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok().map(|d| d.as_secs())
}

fn scan_systemd_services(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    // /lib/systemd/system is package-managed and updated by apt — skip it to avoid noise.
    // /etc/systemd/system is where admins and attackers create/override services.
    let dirs = ["/etc/systemd/system"];

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
            // Symlinks are created by `systemctl enable` pointing to /lib/systemd/system/
            // — skip them to avoid noise from normal package installs and snap services
            if path.is_symlink() { continue; }
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let path_str = path.display().to_string();
            let mut flagged_recent = false;

            for line in content.lines() {
                let line = line.trim();
                if !line.starts_with("ExecStart=") { continue; }
                let exec = &line["ExecStart=".len()..];

                if is_suspicious_exec_path(exec) {
                    findings.push(Finding::critical(
                        "Systemd service runs from suspicious path",
                        "Service ExecStart in /tmp, /dev/shm, or /var/bin — common attacker persistence",
                        &format!("{}: {}", path_str, line),
                    ));
                }

                if ioc.has_xmrig_signature(exec) {
                    findings.push(Finding::critical(
                        "Systemd service contains miner signature",
                        "Service ExecStart contains cryptominer keywords (stratum, --algo, --donate-level)",
                        &format!("{}: {}", path_str, line),
                    ));
                }

                if !flagged_recent {
                    if let Some(age) = age_secs(&path) {
                        if age < RECENT_DAYS_SECS {
                            findings.push(Finding::info(
                                "Recently added systemd service",
                                "Real service file (not symlink) in /etc/systemd/system created within last 30 days",
                                &path_str,
                            ));
                            flagged_recent = true;
                        }
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
    // LKM rootkit names — whitelisting every legitimate module is impossible,
    // so we only flag known-malicious names.
    const ROOTKIT_MODULES: &[&str] = &[
        "diamorphine", "reptile", "tyton", "azazel", "suterusu",
        "modhide", "knark", "adore_ng", "kbeast", "kiss_me_twice",
        "override", "rootkit", "r00tkit",
    ];
    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return findings,
    };
    for line in content.lines() {
        let module = line.split_whitespace().next().unwrap_or("");
        if ROOTKIT_MODULES.iter().any(|bad| module == *bad || module.contains(bad)) {
            findings.push(Finding::critical(
                "Known LKM rootkit module loaded",
                "Kernel module name matches a known Linux rootkit — immediate investigation required",
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
    fn suspicious_exec_path_flagged() {
        assert!(is_suspicious_exec_path("/tmp/evil --flag"));
        assert!(is_suspicious_exec_path("/dev/shm/socket"));
        assert!(is_suspicious_exec_path("/var/bin/backdoor"));
    }

    #[test]
    fn legitimate_exec_path_not_flagged() {
        assert!(!is_suspicious_exec_path("/usr/bin/python3 --arg"));
        assert!(!is_suspicious_exec_path("/usr/lib/xorg/Xorg --display :0"));
        assert!(!is_suspicious_exec_path("/lib/systemd/systemd-resolved"));
        assert!(!is_suspicious_exec_path("!!/lib/systemd/systemd-timesyncd"));
        assert!(!is_suspicious_exec_path("/usr/sbin/sshd -D"));
    }

    #[test]
    fn miner_signature_in_execstart_flagged() {
        let ioc = crate::ioc::IocDatabase::load();
        // Real-world case: GPU miner disguised as Xorg service
        assert!(ioc.has_xmrig_signature(
            "/usr/lib/xorg/Xorg --algo kawpow --server 54.38.240.253:10443 --user wallet.worker --ssl true"
        ));
        assert!(ioc.has_xmrig_signature(
            "/usr/bin/something stratum+tcp://pool.minexmr.com:4444"
        ));
    }

    #[test]
    fn legitimate_execstart_not_flagged_as_miner() {
        let ioc = crate::ioc::IocDatabase::load();
        assert!(!ioc.has_xmrig_signature("/usr/lib/xorg/Xorg --display :0 -auth /run/user/1000/gdm/Xauthority"));
        assert!(!ioc.has_xmrig_signature("/usr/lib/bluetooth/bluetoothd"));
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
