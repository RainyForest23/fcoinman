use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;

pub struct ProcessScanner {
    pub ioc: IocDatabase,
}

impl ProcessScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for ProcessScanner {

    fn scan(&self) -> Vec<Finding> {
        list_pids()
            .iter()
            .flat_map(|pid| check_process(pid, &self.ioc))
            .collect()
    }
}

fn list_pids() -> Vec<String> {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.chars().all(|c| c.is_ascii_digit()) { Some(name) } else { None }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn read_proc(pid: &str, file: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, file)).ok()
}

/// Returns cumulative CPU percentage since process start (not instantaneous).
/// Useful for detecting miners that have been running for a while.
fn cpu_percent_since_start(pid: &str) -> Option<f64> {
    let stat = read_proc(pid, "stat")?;
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 22 { return None; }
    let utime: u64 = fields[13].parse().ok()?;
    let stime: u64 = fields[14].parse().ok()?;
    let start_time: u64 = fields[21].parse().ok()?;
    let total_ticks = utime + stime;

    let uptime: f64 = fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;

    let hertz = 100u64;
    let elapsed = uptime - (start_time as f64 / hertz as f64);
    if elapsed <= 0.0 { return None; }
    Some(total_ticks as f64 / hertz as f64 / elapsed * 100.0)
}

fn exe_path(pid: &str) -> String {
    fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn cmdline(pid: &str) -> String {
    read_proc(pid, "cmdline")
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

pub fn check_process(pid: &str, ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exe = exe_path(pid);
    let cmd = cmdline(pid);

    // XMRig / P2PInfect cmdline signatures
    if ioc.has_xmrig_signature(&cmd) {
        findings.push(Finding::critical(
            "Process matches XMRig cryptominer signature",
            "Command line contains known miner flags (--donate-level, stratum+tcp://)",
            &format!("pid={} exe={} cmd={}", pid, exe, &cmd[..cmd.len().min(120)]),
        ));
    }

    for sig in &ioc.p2pinfect_signatures {
        if cmd.contains(sig.as_str()) || exe.contains(sig.as_str()) {
            findings.push(Finding::critical(
                "Process matches P2PInfect botnet signature",
                "P2PInfect is the most prevalent Linux SSH botnet as of 2025",
                &format!("pid={} exe={}", pid, exe),
            ));
        }
    }

    // Running from suspicious path
    if !exe.is_empty() && ioc.is_suspicious_path(&exe) {
        findings.push(Finding::warning(
            "Process running from suspicious path",
            "Malware commonly executes from /tmp, /dev/shm, /var/bin",
            &format!("pid={} exe={}", pid, exe),
        ));
    }

    // High CPU
    if let Some(cpu) = cpu_percent_since_start(pid) {
        if cpu > 80.0 {
            findings.push(Finding::warning(
                "High CPU process detected",
                "Sustained >80% CPU since process start — possible cryptominer",
                &format!("pid={} cpu={:.1}% exe={}", pid, cpu, exe),
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocDatabase;

    #[test]
    fn pid_list_not_empty_on_linux() {
        let pids = list_pids();
        // On macOS /proc doesn't exist so pids will be empty — that's fine
        // On Linux this must not be empty
        #[cfg(target_os = "linux")]
        assert!(!pids.is_empty());
        let _ = pids; // suppress unused warning on macOS
    }

    #[test]
    fn xmrig_cmdline_flagged() {
        let ioc = IocDatabase::load();
        assert!(ioc.has_xmrig_signature("--donate-level 1 stratum+tcp://pool.example.com:3333"));
    }

    #[test]
    fn normal_process_not_flagged() {
        let ioc = IocDatabase::load();
        assert!(!ioc.has_xmrig_signature("sshd -D"));
        assert!(!ioc.has_xmrig_signature("nginx -g daemon off"));
    }

    #[test]
    fn suspicious_path_detected() {
        let ioc = IocDatabase::load();
        assert!(ioc.is_suspicious_path("/tmp/backdoor"));
        assert!(ioc.is_suspicious_path("/dev/shm/miner"));
    }
}
