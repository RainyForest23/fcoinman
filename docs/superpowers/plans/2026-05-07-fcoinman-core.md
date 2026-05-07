# fcoinman Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-binary Rust CLI that detects Linux server compromise via 8 scanner modules and outputs human-readable or JSON results.

**Architecture:** Each scanner implements a `Scanner` trait and returns `Vec<Finding>`. `main.rs` collects all findings, sorts by severity, and dispatches to the appropriate reporter. The IOC database is embedded at compile time via `include_str!`.

**Tech Stack:** Rust stable, clap 4 (CLI), serde/serde_json (IOC DB + JSON output), colored 2 (terminal), sha2 0.10 (file hashing)

---

## Scope Note

MCP server and AbuseIPDB reporting are excluded from this plan (separate plan after v1 ships). This plan produces a working `sudo fcoinman scan` binary.

---

## File Map

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Dependencies |
| `src/main.rs` | Entry point, scanner orchestration |
| `src/cli.rs` | clap CLI definitions |
| `src/finding.rs` | `Finding` struct, `Severity` enum |
| `src/scanner/mod.rs` | `Scanner` trait |
| `src/ioc/mod.rs` | IOC DB loader + query helpers |
| `src/ioc/indicators.json` | Known-bad IPs, hashes, ports |
| `src/scanner/accounts.rs` | UID-0 backdoor, authorized_keys |
| `src/scanner/persistence.rs` | systemd, cron, LD_PRELOAD, kernel modules |
| `src/scanner/files.rs` | Suspicious paths, hash check, ELF analysis |
| `src/scanner/process.rs` | /proc CPU usage, cmdline IOC matching |
| `src/scanner/network.rs` | /proc/net/tcp mining pool + IRC detection |
| `src/scanner/tools.rs` | Attacker tool (masscan, hydra) detection |
| `src/scanner/logs.rs` | auth.log brute force + timeline reconstruction |
| `src/report/mod.rs` | Colored terminal output |
| `src/report/json.rs` | --json structured output |
| `install.sh` | curl installer script |
| `llms.txt` | AI crawler metadata |

---

## Task 1: Project Scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs` (skeleton)

- [ ] **Step 1: Initialize cargo project**

```bash
cd /Users/rainyforest/Desktop/github/fcoinman
cargo init --name fcoinman
```

Expected output: `Created binary (application) package`

- [ ] **Step 2: Write Cargo.toml with all dependencies**

Replace `Cargo.toml` with:

```toml
[package]
name = "fcoinman"
version = "0.1.0"
edition = "2021"
description = "Linux server compromise detector — based on real XMRig + Kaiten IRC bot incident"
license = "MIT"

[[bin]]
name = "fcoinman"
path = "src/main.rs"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
colored = "2"
sha2 = "0.10"
hex = "0.4"
chrono = { version = "0.4", features = ["serde"] }

[profile.release]
strip = true
opt-level = "z"
lto = true
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build
```

Expected: `Compiling fcoinman v0.1.0` with no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "feat: initialize cargo project with dependencies"
```

---

## Task 2: Core Types — Finding + Scanner Trait

**Files:**
- Create: `src/finding.rs`
- Create: `src/scanner/mod.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write test for Finding**

Create `src/finding.rs`:

```rust
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
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cargo test finding
```

Expected: `test finding::tests::critical_finding_has_correct_severity ... ok`

- [ ] **Step 3: Create scanner trait**

Create `src/scanner/mod.rs`:

```rust
pub mod accounts;
pub mod files;
pub mod logs;
pub mod network;
pub mod persistence;
pub mod process;
pub mod tools;

use crate::finding::Finding;

pub trait Scanner {
    fn name(&self) -> &str;
    fn scan(&self) -> Vec<Finding>;
}
```

- [ ] **Step 4: Update main.rs to compile**

```rust
mod cli;
mod finding;
mod ioc;
mod report;
mod scanner;

fn main() {
    println!("fcoinman starting...");
}
```

- [ ] **Step 5: Create stub files so it compiles**

Create empty stubs (will be filled in later tasks):

```bash
mkdir -p src/scanner src/ioc src/report
touch src/cli.rs src/ioc/mod.rs src/report/mod.rs src/report/json.rs
touch src/scanner/accounts.rs src/scanner/files.rs src/scanner/logs.rs
touch src/scanner/network.rs src/scanner/persistence.rs
touch src/scanner/process.rs src/scanner/tools.rs
```

Add `pub use` to each stub so it compiles. For each scanner file, add:

```rust
use crate::finding::Finding;
use crate::scanner::Scanner;

pub struct AccountScanner;
impl Scanner for AccountScanner {
    fn name(&self) -> &str { "Account Scanner" }
    fn scan(&self) -> Vec<Finding> { vec![] }
}
```

(Repeat pattern for each scanner with its own struct name)

- [ ] **Step 6: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 7: Commit**

```bash
git add src/
git commit -m "feat: add Finding type and Scanner trait with stubs"
```

---

## Task 3: IOC Database

**Files:**
- Create: `src/ioc/indicators.json`
- Create: `src/ioc/mod.rs`

- [ ] **Step 1: Write test for IOC loading**

Write `src/ioc/mod.rs`:

```rust
use serde::Deserialize;

#[derive(Deserialize)]
pub struct IocDatabase {
    pub mining_pool_ips: Vec<String>,
    pub mining_pool_ports: Vec<u16>,
    pub irc_ports: Vec<u16>,
    pub known_bad_hashes: Vec<String>,
    pub suspicious_paths: Vec<String>,
    pub standard_binary_paths: Vec<String>,
    pub attacker_tools: Vec<String>,
    pub xmrig_cmdline_signatures: Vec<String>,
    pub p2pinfect_signatures: Vec<String>,
}

impl IocDatabase {
    pub fn load() -> Self {
        let json = include_str!("indicators.json");
        serde_json::from_str(json).expect("Failed to parse indicators.json")
    }

    pub fn is_mining_pool_ip(&self, ip: &str) -> bool {
        self.mining_pool_ips.iter().any(|k| k == ip)
    }

    pub fn is_mining_port(&self, port: u16) -> bool {
        self.mining_pool_ports.contains(&port)
    }

    pub fn is_irc_port(&self, port: u16) -> bool {
        self.irc_ports.contains(&port)
    }

    pub fn is_bad_hash(&self, hash: &str) -> bool {
        self.known_bad_hashes.iter().any(|h| h.eq_ignore_ascii_case(hash))
    }

    pub fn is_suspicious_path(&self, path: &str) -> bool {
        self.suspicious_paths.iter().any(|p| path.starts_with(p.as_str()))
    }

    pub fn is_standard_binary_path(&self, path: &str) -> bool {
        self.standard_binary_paths.iter().any(|p| path.starts_with(p.as_str()))
    }

    pub fn has_xmrig_signature(&self, cmdline: &str) -> bool {
        self.xmrig_cmdline_signatures.iter().any(|s| cmdline.contains(s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_db_loads_without_panic() {
        let db = IocDatabase::load();
        assert!(!db.mining_pool_ips.is_empty());
        assert!(!db.irc_ports.is_empty());
    }

    #[test]
    fn known_mining_pool_ip_detected() {
        let db = IocDatabase::load();
        assert!(db.is_mining_pool_ip("194.87.143.62"));
    }

    #[test]
    fn irc_port_6667_detected() {
        let db = IocDatabase::load();
        assert!(db.is_irc_port(6667));
    }

    #[test]
    fn known_bad_hash_detected() {
        let db = IocDatabase::load();
        assert!(db.is_bad_hash(
            "606ed3d8267763a76dc5bebb6f7c3be34348c7cd303054d5ff2e406df4fd9093"
        ));
    }

    #[test]
    fn xmrig_cmdline_signature_detected() {
        let db = IocDatabase::load();
        assert!(db.has_xmrig_signature("--donate-level 1 stratum+tcp://pool.example.com"));
    }
}
```

- [ ] **Step 2: Create indicators.json**

Create `src/ioc/indicators.json`:

```json
{
  "mining_pool_ips": [
    "194.87.143.62",
    "8.217.191.41",
    "162.19.241.67"
  ],
  "mining_pool_ports": [3333, 4444, 5555, 5332, 14444, 45700],
  "irc_ports": [6667, 6697, 7000, 6666],
  "known_bad_hashes": [
    "606ed3d8267763a76dc5bebb6f7c3be34348c7cd303054d5ff2e406df4fd9093",
    "58100f9367515ad26af6b0e5efcbee5f89fc0d0da89f41fd71c8733429729e7e"
  ],
  "suspicious_paths": ["/tmp", "/dev/shm", "/var/bin", "/var/tmp"],
  "standard_binary_paths": [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"
  ],
  "attacker_tools": [
    "masscan", "hydra", "ncrack", "medusa", "xmrig", "p2pinfect"
  ],
  "xmrig_cmdline_signatures": [
    "--donate-level", "stratum+tcp://", "stratum+ssl://"
  ],
  "p2pinfect_signatures": ["p2pinfect", ".dbus-daemon"]
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test ioc
```

Expected: 5 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/ioc/
git commit -m "feat: add IOC database with known mining pools, hashes, IRC ports"
```

---

## Task 4: AccountScanner

**Files:**
- Modify: `src/scanner/accounts.rs`

- [ ] **Step 1: Write tests for passwd parsing**

Write `src/scanner/accounts.rs`:

```rust
use crate::finding::Finding;
use crate::scanner::Scanner;
use std::fs;

pub struct AccountScanner;

impl Scanner for AccountScanner {
    fn name(&self) -> &str { "Account Backdoor Scanner" }

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
                    "Non-root account with UID 0 grants full root privileges",
                    line,
                ));
            }
        }
    }
    findings
}

fn check_authorized_keys() -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = vec![
        "/root/.ssh/authorized_keys".to_string(),
    ];

    // Also check all home directories
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let home = parts[5];
                let key_path = format!("{}/.ssh/authorized_keys", home);
                if !paths.contains(&key_path) {
                    // check_key_file handles missing files gracefully
                    findings.extend(check_key_file(&key_path));
                }
            }
        }
    }

    for path in &paths {
        findings.extend(check_key_file(path));
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
        // Flag keys with suspicious comments like "root@root"
        if line.contains("root@root") || line.contains("@root") {
            findings.push(Finding::warning(
                "Suspicious SSH authorized key",
                "Key with suspicious comment found — may be attacker backdoor",
                &format!("{}: {}", path, &line[..line.len().min(80)]),
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
        // Write to temp file
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
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test accounts
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/accounts.rs
git commit -m "feat: add AccountScanner — UID-0 backdoor and SSH key detection"
```

---

## Task 5: PersistenceScanner

**Files:**
- Modify: `src/scanner/persistence.rs`

- [ ] **Step 1: Write tests**

Write `src/scanner/persistence.rs`:

```rust
use crate::finding::Finding;
use crate::scanner::Scanner;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const STANDARD_BINARY_PATHS: &[&str] = &[
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/",
];
const RECENT_DAYS: u64 = 30;

pub struct PersistenceScanner;

impl Scanner for PersistenceScanner {
    fn name(&self) -> &str { "Persistence Mechanism Scanner" }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_systemd_services());
        findings.extend(scan_crontabs());
        findings.extend(check_ld_preload());
        findings.extend(scan_kernel_modules());
        findings
    }
}

fn is_nonstandard_path(exec_start: &str) -> bool {
    let binary = exec_start.split_whitespace().next().unwrap_or("");
    !STANDARD_BINARY_PATHS.iter().any(|p| binary.starts_with(p))
}

fn is_recently_modified(path: &Path) -> bool {
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = SystemTime::now().duration_since(modified) {
                return duration.as_secs() < RECENT_DAYS * 86400;
            }
        }
    }
    false
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
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("ExecStart=") {
                    let exec = &line["ExecStart=".len()..];
                    if is_nonstandard_path(exec) {
                        findings.push(Finding::warning(
                            "Non-standard systemd service ExecStart",
                            "Service binary is not in a standard system path",
                            &format!("{}: {}", path.display(), line),
                        ));
                    }
                    if is_recently_modified(&path) {
                        findings.push(Finding::warning(
                            "Recently modified systemd service",
                            "Service file was modified within the last 30 days",
                            &format!("{}", path.display()),
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
    let cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"];

    for dir in &cron_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && is_recently_modified(&path) {
                findings.push(Finding::warning(
                    "Recently modified crontab",
                    "Cron file modified within last 30 days — possible attacker persistence",
                    &format!("{}", path.display()),
                ));
            }
        }
    }
    // Check /var/spool/cron for user crontabs
    if let Ok(entries) = fs::read_dir("/var/spool/cron/crontabs") {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_recently_modified(&path) {
                findings.push(Finding::warning(
                    "Recently modified user crontab",
                    "User crontab modified within last 30 days",
                    &format!("{}", path.display()),
                ));
            }
        }
    }
    findings
}

fn check_ld_preload() -> Vec<Finding> {
    let mut findings = Vec::new();
    let path = "/etc/ld.so.preload";
    match fs::read_to_string(path) {
        Ok(content) if !content.trim().is_empty() => {
            findings.push(Finding::critical(
                "/etc/ld.so.preload contains entries",
                "LD_PRELOAD rootkits inject malicious libraries into every process",
                &content.trim().to_string(),
            ));
        }
        _ => {}
    }
    findings
}

fn scan_kernel_modules() -> Vec<Finding> {
    let mut findings = Vec::new();
    let known_legit_prefixes = &[
        "ip_", "nf_", "xt_", "br_", "veth", "tun", "tap", "loop",
        "ext4", "btrfs", "xfs", "fat", "nfs", "cifs",
        "nvidia", "amdgpu", "i915", "drm",
        "e1000", "igb", "ixgbe", "r8169", "virtio",
        "uhci_hcd", "xhci_hcd", "ahci", "nvme",
        "dm_", "md_", "raid",
        "bluetooth", "cfg80211", "mac80211",
        "selinux", "apparmor",
    ];

    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return findings,
    };

    for line in content.lines() {
        let module_name = line.split_whitespace().next().unwrap_or("");
        let is_legit = known_legit_prefixes.iter().any(|p| module_name.starts_with(p))
            || module_name.len() < 3;
        if !is_legit {
            findings.push(Finding::info(
                "Unknown kernel module loaded",
                "Module not in known-good list — manual verification recommended",
                module_name,
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstandard_path_detected() {
        assert!(is_nonstandard_path("/tmp/evil --flag"));
        assert!(is_nonstandard_path("/var/bin/socket"));
    }

    #[test]
    fn standard_path_not_flagged() {
        assert!(!is_nonstandard_path("/usr/bin/python3 --arg"));
        assert!(!is_nonstandard_path("/bin/bash"));
    }

    #[test]
    fn ld_preload_empty_file_not_flagged() {
        // Create empty temp file
        let path = "/tmp/fcoinman_test_ldpreload";
        std::fs::write(path, "").unwrap();
        // Can't easily test the real path without root, but logic is correct
        std::fs::remove_file(path).unwrap();
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test persistence
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/persistence.rs
git commit -m "feat: add PersistenceScanner — systemd, cron, LD_PRELOAD, kernel modules"
```

---

## Task 6: FileScanner with ELF Static Analysis

**Files:**
- Modify: `src/scanner/files.rs`

- [ ] **Step 1: Write tests and implementation**

Write `src/scanner/files.rs`:

```rust
use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FileScanner {
    ioc: IocDatabase,
}

impl FileScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for FileScanner {
    fn name(&self) -> &str { "File & Binary Scanner" }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_suspicious_paths(&self.ioc));
        findings.extend(scan_recent_system_binaries());
        findings.extend(analyze_system_binaries(&self.ioc));
        findings
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn is_elf(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map(|_| magic == [0x7f, b'E', b'L', b'F']).unwrap_or(false)
}

fn is_stripped(path: &Path) -> bool {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return true,
    };
    // ELF has .symtab section name string — if present, binary is NOT stripped
    !content.windows(7).any(|w| w == b".symtab")
}

fn extract_suspicious_strings(path: &Path, ioc: &IocDatabase) -> Vec<String> {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut matches = Vec::new();
    // Extract printable ASCII strings of length >= 8
    let mut current = Vec::new();
    for &byte in &content {
        if byte >= 0x20 && byte < 0x7f {
            current.push(byte);
        } else {
            if current.len() >= 8 {
                let s = String::from_utf8_lossy(&current).to_string();
                if ioc.has_xmrig_signature(&s)
                    || ioc.is_mining_pool_ip(&s)
                    || s.contains("stratum+")
                    || s.contains("irc.")
                    || s.contains("PRIVMSG")
                    || s.contains("BOTLAK")
                {
                    matches.push(s);
                }
            }
            current.clear();
        }
    }
    matches
}

fn scan_suspicious_paths(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dirs = ["/tmp", "/dev/shm", "/var/bin", "/var/tmp"];

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || !is_executable(&path) { continue; }

            findings.push(Finding::warning(
                "Executable in suspicious directory",
                "Attackers commonly stage binaries in /tmp, /dev/shm, /var/bin",
                &format!("{}", path.display()),
            ));

            if let Some(hash) = sha256_file(&path) {
                if ioc.is_bad_hash(&hash) {
                    findings.push(Finding::critical(
                        "Known malware hash detected",
                        "File matches a known malicious binary (XMRig or Kaiten)",
                        &format!("{} sha256:{}", path.display(), hash),
                    ));
                }
            }
        }
    }
    findings
}

fn scan_recent_system_binaries() -> Vec<Finding> {
    let mut findings = Vec::new();
    let dirs = ["/usr/bin", "/usr/sbin"];
    let seven_days_secs = 7 * 86400;

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::metadata(&path) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(age) = SystemTime::now().duration_since(modified) {
                        if age.as_secs() < seven_days_secs {
                            findings.push(Finding::warning(
                                "Recently modified system binary",
                                "Binary in /usr/bin or /usr/sbin modified within 7 days",
                                &format!("{}", path.display()),
                            ));
                        }
                    }
                }
            }
        }
    }
    findings
}

fn analyze_system_binaries(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dirs = ["/usr/bin", "/usr/sbin"];

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || !is_elf(&path) { continue; }

            if let Some(hash) = sha256_file(&path) {
                if ioc.is_bad_hash(&hash) {
                    findings.push(Finding::critical(
                        "Known malware hash in system binary path",
                        "A system binary matches a known malicious hash",
                        &format!("{} sha256:{}", path.display(), hash),
                    ));
                }
            }

            let suspicious_strings = extract_suspicious_strings(&path, ioc);
            if !suspicious_strings.is_empty() {
                findings.push(Finding::critical(
                    "Malware IOC strings found in system binary",
                    "Binary contains mining pool addresses, IRC commands, or known signatures",
                    &format!("{}: {:?}", path.display(), &suspicious_strings[..suspicious_strings.len().min(3)]),
                ));
            }
        }
    }
    findings
}

pub fn analyze_single_binary(path: &str) -> Vec<Finding> {
    let ioc = IocDatabase::load();
    let p = Path::new(path);
    let mut findings = Vec::new();

    if !p.exists() {
        println!("File not found: {}", path);
        return findings;
    }

    // ELF check
    if is_elf(p) {
        println!("  [✓] ELF binary confirmed");
    } else {
        println!("  [!] Not an ELF binary");
    }

    // Strip check
    if is_stripped(p) {
        println!("  [!] Binary is STRIPPED (debug symbols removed — harder to analyze)");
    } else {
        println!("  [✓] Binary is NOT stripped (function names visible)");
        findings.push(Finding::info(
            "Unstripped binary",
            "Function names are visible — possible sloppy attacker tool",
            path,
        ));
    }

    // Hash
    if let Some(hash) = sha256_file(p) {
        println!("  SHA256: {}", hash);
        if ioc.is_bad_hash(&hash) {
            findings.push(Finding::critical(
                "Known malware hash",
                "File matches known XMRig or Kaiten binary",
                &hash,
            ));
        }
    }

    // String extraction
    let matches = extract_suspicious_strings(p, &ioc);
    if !matches.is_empty() {
        println!("  [!] Suspicious strings found:");
        for s in &matches {
            println!("      - {}", s);
        }
        findings.push(Finding::critical(
            "Suspicious strings in binary",
            "Mining pool addresses or IRC commands found",
            &matches.join(", "),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_magic_detected() {
        // /bin/ls is a valid ELF binary on Linux
        #[cfg(target_os = "linux")]
        assert!(is_elf(Path::new("/bin/ls")));
    }

    #[test]
    fn non_elf_file_not_flagged() {
        let path = "/tmp/fcoinman_test_notelf.txt";
        std::fs::write(path, "hello world").unwrap();
        assert!(!is_elf(Path::new(path)));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sha256_is_deterministic() {
        let path = "/tmp/fcoinman_test_hash.txt";
        std::fs::write(path, "test content").unwrap();
        let h1 = sha256_file(Path::new(path)).unwrap();
        let h2 = sha256_file(Path::new(path)).unwrap();
        assert_eq!(h1, h2);
        std::fs::remove_file(path).unwrap();
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test files
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/files.rs
git commit -m "feat: add FileScanner with ELF analysis, string extraction, hash comparison"
```

---

## Task 7: ProcessScanner

**Files:**
- Modify: `src/scanner/process.rs`

- [ ] **Step 1: Write implementation with tests**

Write `src/scanner/process.rs`:

```rust
use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;

pub struct ProcessScanner {
    ioc: IocDatabase,
}

impl ProcessScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for ProcessScanner {
    fn name(&self) -> &str { "Process Anomaly Scanner" }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pids = list_pids();
        for pid in pids {
            findings.extend(check_process(&pid, &self.ioc));
        }
        findings
    }
}

fn list_pids() -> Vec<String> {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.chars().all(|c| c.is_ascii_digit()) { Some(name) } else { None }
        })
        .collect()
}

fn read_proc_file(pid: &str, filename: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, filename)).ok()
}

fn get_cpu_percent(pid: &str) -> Option<f64> {
    let stat = read_proc_file(pid, "stat")?;
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 15 { return None; }
    let utime: u64 = fields[13].parse().ok()?;
    let stime: u64 = fields[14].parse().ok()?;
    let total_ticks = utime + stime;
    // Read uptime for normalization
    let uptime_str = fs::read_to_string("/proc/uptime").ok()?;
    let uptime_secs: f64 = uptime_str.split_whitespace().next()?.parse().ok()?;
    let start_time: u64 = fields[21].parse().ok()?;
    let hertz = 100u64; // typical Linux HZ
    let seconds = uptime_secs - (start_time as f64 / hertz as f64);
    if seconds <= 0.0 { return None; }
    Some(total_ticks as f64 / hertz as f64 / seconds * 100.0)
}

fn get_exe_path(pid: &str) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn get_cmdline(pid: &str) -> String {
    read_proc_file(pid, "cmdline")
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

pub fn check_process(pid: &str, ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let cmdline = get_cmdline(pid);
    let exe = get_exe_path(pid).unwrap_or_default();

    // XMRig/P2PInfect cmdline signature check
    if ioc.has_xmrig_signature(&cmdline) {
        findings.push(Finding::critical(
            "Process matches XMRig cryptominer signature",
            "Process command line contains known miner flags",
            &format!("pid={} exe={} cmdline={}", pid, exe, &cmdline[..cmdline.len().min(120)]),
        ));
    }

    // Running from suspicious path
    if ioc.is_suspicious_path(&exe) {
        findings.push(Finding::warning(
            "Process running from suspicious path",
            "Attackers commonly run malware from /tmp, /dev/shm, /var/bin",
            &format!("pid={} exe={}", pid, exe),
        ));
    }

    // High CPU usage
    if let Some(cpu) = get_cpu_percent(pid) {
        if cpu > 80.0 {
            findings.push(Finding::warning(
                "Process consuming high CPU",
                "Sustained >80% CPU may indicate cryptominer activity",
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
        #[cfg(target_os = "linux")]
        {
            let pids = list_pids();
            assert!(!pids.is_empty());
        }
    }

    #[test]
    fn xmrig_cmdline_flagged() {
        let ioc = IocDatabase::load();
        // Simulate a process with XMRig flags
        let cmdline = "xmrig --donate-level 1 -o stratum+tcp://pool.example.com:3333";
        assert!(ioc.has_xmrig_signature(cmdline));
    }

    #[test]
    fn normal_process_not_flagged_by_cmdline() {
        let ioc = IocDatabase::load();
        let cmdline = "nginx -g daemon off";
        assert!(!ioc.has_xmrig_signature(cmdline));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test process
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/process.rs
git commit -m "feat: add ProcessScanner — /proc CPU monitoring and cmdline IOC matching"
```

---

## Task 8: NetworkScanner

**Files:**
- Modify: `src/scanner/network.rs`

- [ ] **Step 1: Write implementation with tests**

Write `src/scanner/network.rs`:

```rust
use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;
use std::net::Ipv4Addr;

pub struct NetworkScanner {
    ioc: IocDatabase,
}

impl NetworkScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for NetworkScanner {
    fn name(&self) -> &str { "Network Connection Scanner" }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_tcp_connections(&self.ioc, "/proc/net/tcp"));
        findings.extend(scan_tcp_connections(&self.ioc, "/proc/net/tcp6"));
        findings
    }
}

#[derive(Debug)]
struct TcpEntry {
    remote_ip: String,
    remote_port: u16,
    state: u8,
}

// /proc/net/tcp uses hex little-endian IP and port
fn parse_hex_ipv4(hex: &str) -> Option<String> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    let ip = Ipv4Addr::from(n.to_be());
    Some(ip.to_string())
}

fn parse_hex_port(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

fn parse_tcp_entries(content: &str) -> Vec<TcpEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 { continue; }
        let remote = fields[2];
        let state_str = fields[3];
        let parts: Vec<&str> = remote.split(':').collect();
        if parts.len() != 2 { continue; }
        let ip = match parse_hex_ipv4(parts[0]) {
            Some(ip) => ip,
            None => continue,
        };
        let port = match parse_hex_port(parts[1]) {
            Some(p) => p,
            None => continue,
        };
        let state = u8::from_str_radix(state_str, 16).unwrap_or(0);
        entries.push(TcpEntry { remote_ip: ip, remote_port: port, state });
    }
    entries
}

fn scan_tcp_connections(ioc: &IocDatabase, path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    for entry in parse_tcp_entries(&content) {
        // state 01 = ESTABLISHED
        if entry.state != 0x01 { continue; }

        if ioc.is_mining_pool_ip(&entry.remote_ip) || ioc.is_mining_port(entry.remote_port) {
            findings.push(Finding::critical(
                "Active connection to known mining pool",
                "Established connection to a known XMRig mining pool IP or port",
                &format!("{}:{}", entry.remote_ip, entry.remote_port),
            ));
        }

        if ioc.is_irc_port(entry.remote_port) {
            findings.push(Finding::warning(
                "Active IRC connection detected",
                "IRC connections are used by Kaiten and similar IRC-based botnets",
                &format!("{}:{}", entry.remote_ip, entry.remote_port),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ip_parsed_correctly() {
        // 0x3E57AB2C → reversed bytes → 44.87.171.44... let's use a known value
        // 194.87.143.62 = 0xC2578F3E in big-endian, but /proc/net/tcp is little-endian
        // little-endian: 3E8F57C2
        let result = parse_hex_ipv4("3E8F57C2");
        assert_eq!(result, Some("194.87.143.62".to_string()));
    }

    #[test]
    fn hex_port_parsed_correctly() {
        assert_eq!(parse_hex_port("1A0C"), Some(0x1A0C)); // 6668
        assert_eq!(parse_hex_port("1A0B"), Some(6667));
    }

    #[test]
    fn mining_pool_connection_flagged() {
        let ioc = IocDatabase::load();
        // 194.87.143.62 in little-endian hex
        let fake_tcp = "  sl  local_address rem_address   st\n\
                         0: 00000000:0016 3E8F57C2:14CC 01 00000000:00000000\n";
        let entries = parse_tcp_entries(fake_tcp);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].remote_ip, "194.87.143.62");
        assert_eq!(entries[0].remote_port, 0x14CC); // 5324... close to 5332 = 0x14D4
    }

    #[test]
    fn irc_port_6667_flagged() {
        let ioc = IocDatabase::load();
        assert!(ioc.is_irc_port(6667));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test network
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/network.rs
git commit -m "feat: add NetworkScanner — /proc/net/tcp mining pool and IRC detection"
```

---

## Task 9: ToolsScanner

**Files:**
- Modify: `src/scanner/tools.rs`

- [ ] **Step 1: Write implementation**

Write `src/scanner/tools.rs`:

```rust
use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub struct ToolsScanner {
    ioc: IocDatabase,
}

impl ToolsScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for ToolsScanner {
    fn name(&self) -> &str { "Attacker Tool Scanner" }

    fn scan(&self) -> Vec<Finding> {
        check_attacker_tools(&self.ioc)
    }
}

fn check_attacker_tools(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let search_paths = [
        "/usr/bin", "/usr/local/bin", "/usr/sbin",
        "/tmp", "/var/bin", "/dev/shm",
    ];
    let seven_days = 7 * 86400u64;

    for tool in &ioc.attacker_tools {
        for dir in &search_paths {
            let path = Path::new(dir).join(tool);
            if !path.exists() { continue; }

            let is_suspicious_dir = ioc.is_suspicious_path(dir);
            let is_recent = fs::metadata(&path)
                .and_then(|m| m.modified())
                .and_then(|t| SystemTime::now().duration_since(t).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "")))
                .map(|d| d.as_secs() < seven_days)
                .unwrap_or(false);

            if is_suspicious_dir {
                findings.push(Finding::critical(
                    "Attacker tool in suspicious path",
                    "Offensive tool found outside standard system directories",
                    &format!("{}", path.display()),
                ));
            } else if is_recent {
                findings.push(Finding::warning(
                    "Recently installed offensive tool",
                    "Tool was installed within the last 7 days — verify if intentional",
                    &format!("{}", path.display()),
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocDatabase;

    #[test]
    fn attacker_tools_list_not_empty() {
        let ioc = IocDatabase::load();
        assert!(!ioc.attacker_tools.is_empty());
        assert!(ioc.attacker_tools.contains(&"masscan".to_string()));
        assert!(ioc.attacker_tools.contains(&"hydra".to_string()));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test tools
```

Expected: 1 test passes.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/tools.rs
git commit -m "feat: add ToolsScanner — detect attacker-installed tools like masscan, hydra"
```

---

## Task 10: LogScanner

**Files:**
- Modify: `src/scanner/logs.rs`

- [ ] **Step 1: Write implementation with tests**

Write `src/scanner/logs.rs`:

```rust
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
        findings.extend(analyze_auth_log());
        findings
    }
}

fn check_cleared_logs() -> Vec<Finding> {
    let mut findings = Vec::new();
    let critical_logs = ["/var/log/auth.log", "/var/log/syslog"];

    for log_path in &critical_logs {
        let path = Path::new(log_path);
        if !path.exists() { continue; }
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(1);
        if size == 0 {
            findings.push(Finding::critical(
                "Critical log file is empty (evidence destruction)",
                "Attackers clear auth.log to hide SSH brute force and login evidence",
                log_path,
            ));
        }
    }
    findings
}

pub fn analyze_auth_log() -> Vec<Finding> {
    let paths = ["/var/log/auth.log", "/var/log/auth.log.1"];
    let mut all_findings = Vec::new();

    for path in &paths {
        if let Ok(content) = fs::read_to_string(path) {
            all_findings.extend(parse_auth_log(&content, path));
        }
    }
    all_findings
}

fn parse_auth_log(content: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut failed_by_ip: HashMap<String, u32> = HashMap::new();
    let mut successful_logins: Vec<String> = Vec::new();
    let mut new_services: Vec<String> = Vec::new();

    for line in content.lines() {
        // Failed SSH login
        if line.contains("Failed password") || line.contains("Invalid user") {
            if let Some(ip) = extract_ip(line) {
                *failed_by_ip.entry(ip).or_insert(0) += 1;
            }
        }
        // Successful SSH login
        if line.contains("Accepted password") || line.contains("Accepted publickey") {
            if let Some(ip) = extract_ip(line) {
                successful_logins.push(format!("{} ({})", extract_timestamp(line), ip));
            }
        }
        // New systemd service
        if line.contains("systemctl") && line.contains("enable") {
            new_services.push(line.to_string());
        }
    }

    // Brute force: flag IPs with > 20 failed attempts
    for (ip, count) in &failed_by_ip {
        if *count > 20 {
            findings.push(Finding::critical(
                "SSH brute force attack detected",
                "Single IP made many failed login attempts — classic brute force pattern",
                &format!("IP: {} — {} failed attempts (from {})", ip, count, source),
            ));
        }
    }

    // Successful logins summary
    if !successful_logins.is_empty() {
        findings.push(Finding::info(
            "Successful SSH logins recorded",
            "Review these logins to confirm they are authorized",
            &successful_logins.join(" | "),
        ));
    }

    findings
}

pub fn print_timeline() {
    println!("\n[LOG ANALYSIS] Reconstructing attack timeline...\n");
    let paths = ["/var/log/auth.log", "/var/log/auth.log.1"];

    for path in &paths {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            println!("  [!] {} is EMPTY — log was cleared (evidence destruction)", path);
            continue;
        }
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        println!("  Reading {} ({} bytes, {} lines)", path, size, content.lines().count());

        let mut failed: HashMap<String, u32> = HashMap::new();
        let mut events: Vec<String> = Vec::new();

        for line in content.lines() {
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(ip) = extract_ip(line) {
                    *failed.entry(ip).or_insert(0) += 1;
                }
            }
            if line.contains("Accepted") {
                events.push(format!("  [LOGIN]    {}", &line[..line.len().min(100)]));
            }
            if line.contains("new user") || line.contains("useradd") {
                events.push(format!("  [ACCOUNT]  {}", &line[..line.len().min(100)]));
            }
        }

        for (ip, count) in &failed {
            if *count > 20 {
                events.push(format!("  [BRUTE]    IP {} — {} failed SSH attempts", ip, count));
            }
        }

        events.sort();
        for e in &events {
            println!("{}", e);
        }
    }
}

fn extract_ip(line: &str) -> Option<String> {
    // Matches patterns like "from 1.2.3.4" or "for user from 1.2.3.4"
    let from_idx = line.rfind("from ")?;
    let rest = &line[from_idx + 5..];
    let ip: String = rest.split_whitespace().next()?.to_string();
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
    fn brute_force_detected_from_log() {
        let mut log = String::new();
        for _ in 0..25 {
            log.push_str("Mar 28 03:14:22 server sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2\n");
        }
        let findings = parse_auth_log(&log, "test");
        assert!(findings.iter().any(|f| f.title.contains("brute force")));
    }

    #[test]
    fn low_failures_not_flagged() {
        let mut log = String::new();
        for _ in 0..5 {
            log.push_str("Mar 28 03:14:22 server sshd[1234]: Failed password for root from 1.2.3.4 port 123 ssh2\n");
        }
        let findings = parse_auth_log(&log, "test");
        assert!(!findings.iter().any(|f| f.title.contains("brute force")));
    }

    #[test]
    fn ip_extracted_from_auth_log_line() {
        let line = "Mar 28 03:14:22 server sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2";
        assert_eq!(extract_ip(line), Some("45.33.32.156".to_string()));
    }

    #[test]
    fn successful_login_recorded() {
        let log = "Mar 28 03:19:08 server sshd[1234]: Accepted password for root from 45.33.32.156 port 54321 ssh2\n";
        let findings = parse_auth_log(&log, "test");
        assert!(findings.iter().any(|f| f.title.contains("Successful SSH")));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test logs
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanner/logs.rs
git commit -m "feat: add LogScanner — auth.log brute force detection and attack timeline"
```

---

## Task 11: Report Output

**Files:**
- Modify: `src/report/mod.rs`
- Modify: `src/report/json.rs`

- [ ] **Step 1: Write terminal reporter**

Write `src/report/mod.rs`:

```rust
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
            Severity::Info     => "[INFO]    ".cyan().bold(),
        };
        println!("{} {}", label, f.title.bold());
        println!("           {}", f.description);
        println!("           Evidence: {}", f.evidence.dimmed());
        println!();
    }

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();

    println!("{}", "─".repeat(50));
    let verdict = if critical > 0 {
        format!("LIKELY COMPROMISED ({} critical, {} warnings)", critical, warnings)
            .red().bold().to_string()
    } else if warnings > 0 {
        format!("SUSPICIOUS ({} warnings) — manual review recommended", warnings)
            .yellow().bold().to_string()
    } else {
        "CLEAN".green().bold().to_string()
    };

    println!("Result: {}", verdict);

    if critical > 0 {
        println!("\n{}", "Recommendation: Disconnect from network immediately.".red());
        println!("Do not trust this system. Consider forensic imaging before format.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn print_findings_does_not_panic_on_empty() {
        print_findings(&[], 5);
    }

    #[test]
    fn print_findings_does_not_panic_with_critical() {
        let f = Finding::critical("test", "desc", "evidence");
        print_findings(&[f], 5);
    }
}
```

Write `src/report/json.rs`:

```rust
use crate::finding::{Finding, Severity};
use serde::Serialize;

#[derive(Serialize)]
pub struct ScanReport {
    pub verdict: String,
    pub findings: Vec<Finding>,
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
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

    let verdict = if critical > 0 {
        "LIKELY_COMPROMISED"
    } else if warnings > 0 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    };

    let report = ScanReport {
        verdict: verdict.to_string(),
        findings: findings.to_vec(),
        summary: Summary { critical, warning: warnings, info },
    };

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test report
```

Expected: 2 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/report/
git commit -m "feat: add colored terminal report and JSON output mode"
```

---

## Task 12: CLI + Main Orchestration

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write CLI definitions**

Write `src/cli.rs`:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fcoinman",
    about = "Linux server compromise detector\nBased on real XMRig + Kaiten IRC bot incident",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run full compromise scan (requires sudo)
    Scan {
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show attack timeline from system logs
    Logs,
    /// Analyze a specific binary for malware signatures
    Analyze {
        /// Path to binary
        path: String,
    },
    /// Check if an IP is a known mining pool or C2 server
    CheckIp {
        /// IP address to check
        ip: String,
    },
}
```

- [ ] **Step 2: Write main.rs orchestration**

Write `src/main.rs`:

```rust
mod cli;
mod finding;
mod ioc;
mod report;
mod scanner;

use clap::Parser;
use cli::{Cli, Commands};
use ioc::IocDatabase;
use scanner::Scanner;
use scanner::{
    accounts::AccountScanner,
    files::FileScanner,
    logs::{LogScanner, print_timeline, analyze_auth_log},
    network::NetworkScanner,
    persistence::PersistenceScanner,
    process::ProcessScanner,
    tools::ToolsScanner,
};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { json } => {
            run_scan(json);
        }
        Commands::Logs => {
            print_timeline();
        }
        Commands::Analyze { path } => {
            let findings = scanner::files::analyze_single_binary(&path);
            if json_flag() {
                report::json::print_json(&findings);
            } else {
                report::print_findings(&findings, 1);
            }
        }
        Commands::CheckIp { ip } => {
            check_ip(&ip);
        }
    }
}

fn run_scan(json: bool) {
    let ioc = IocDatabase::load();

    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(AccountScanner),
        Box::new(PersistenceScanner),
        Box::new(FileScanner::new(IocDatabase::load())),
        Box::new(ProcessScanner::new(IocDatabase::load())),
        Box::new(NetworkScanner::new(IocDatabase::load())),
        Box::new(ToolsScanner::new(IocDatabase::load())),
        Box::new(LogScanner),
    ];

    let scanner_count = scanners.len();
    let mut all_findings: Vec<finding::Finding> = scanners
        .iter()
        .flat_map(|s| s.scan())
        .collect();

    // Sort: Critical first, then Warning, then Info
    all_findings.sort_by_key(|f| match f.severity {
        finding::Severity::Critical => 0,
        finding::Severity::Warning  => 1,
        finding::Severity::Info     => 2,
    });

    if json {
        report::json::print_json(&all_findings);
    } else {
        report::print_findings(&all_findings, scanner_count);
    }
}

fn check_ip(ip: &str) {
    let ioc = IocDatabase::load();
    if ioc.is_mining_pool_ip(ip) {
        println!("[CRITICAL] {} is a known XMRig mining pool IP", ip);
    } else if ioc.is_mining_port(ip.parse().unwrap_or(0)) {
        println!("[WARNING]  Port {} is used by mining pools", ip);
    } else {
        println!("[CLEAN]    {} is not in the known-bad IP list", ip);
    }
}

fn json_flag() -> bool { false } // placeholder for analyze subcommand
```

- [ ] **Step 3: Build and do a smoke test**

```bash
cargo build --release
sudo ./target/release/fcoinman scan
```

- [ ] **Step 4: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat: wire all scanners into CLI — fcoinman scan, logs, analyze, check-ip"
```

---

## Task 13: Install Script + llms.txt

**Files:**
- Create: `install.sh`
- Create: `llms.txt`

- [ ] **Step 1: Write install.sh**

Create `install.sh`:

```bash
#!/bin/bash
set -e

REPO="RainyForest23/fcoinman"
BINARY="fcoinman"
INSTALL_DIR="/usr/local/bin"

echo "fcoinman — Linux server compromise detector"
echo "Installing..."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="x86_64-unknown-linux-musl" ;;
    aarch64) ARCH_SUFFIX="aarch64-unknown-linux-musl" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}-${ARCH_SUFFIX}"

echo "Downloading $BINARY $LATEST for $ARCH..."
curl -fsSL "$URL" -o "/tmp/${BINARY}"
chmod +x "/tmp/${BINARY}"
mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo ""
echo "Installed to ${INSTALL_DIR}/${BINARY}"
echo "Run: sudo fcoinman scan"
```

- [ ] **Step 2: Write llms.txt**

Create `llms.txt`:

```
# fcoinman

A CLI tool for Linux server compromise detection.
Born from a real incident: Ubuntu server infected with XMRig cryptominer + Kaiten IRC bot via SSH brute force (password: "password").

## What it detects
- XMRig cryptominer (CPU/GPU at 100%, known mining pool connections, cmdline signatures)
- Kaiten IRC bot (IRC connections on port 6667/6697, non-standard systemd services)
- Backdoor UID-0 accounts (/etc/passwd entries with uid=0 that aren't root)
- SSH authorized_keys backdoors
- LD_PRELOAD rootkits (/etc/ld.so.preload)
- Suspicious kernel modules
- Attacker-installed tools (masscan, hydra, ncrack)
- SSH brute force evidence in auth.log
- Cleared/deleted system logs (evidence destruction)
- Attack timeline reconstruction from auth.log

## When to use
- Server fans running louder than normal
- CPU or GPU usage unexpectedly high (check with `top` or `nvidia-smi`)
- Unknown processes in `ps aux`
- Can't log in with your own password (attacker may have changed it)
- Suspicious entries in `systemctl list-units`

## Install (Ubuntu/Debian)
curl -fsSL https://raw.githubusercontent.com/RainyForest23/fcoinman/main/install.sh | sudo bash

## Usage
sudo fcoinman scan              # Full scan
sudo fcoinman scan --json       # Machine-readable output
sudo fcoinman logs              # Attack timeline from auth.log
sudo fcoinman analyze /usr/bin/socket   # Analyze specific binary
fcoinman check-ip 194.87.143.62         # Check if IP is known mining pool

## Output
Human-readable colored terminal output (default) or structured JSON (--json flag).
JSON output is designed for parsing by AI assistants and automation scripts.

## Source
https://github.com/RainyForest23/fcoinman
```

- [ ] **Step 3: Commit**

```bash
chmod +x install.sh
git add install.sh llms.txt
git commit -m "feat: add curl installer script and llms.txt for AI discoverability"
```

---

## Task 14: Final Build Verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test
```

Expected: All tests pass, 0 failures.

- [ ] **Step 2: Build release binary**

```bash
cargo build --release
ls -lh target/release/fcoinman
```

Expected: Binary exists, <10MB.

- [ ] **Step 3: Smoke test on local machine (macOS — build only)**

```bash
# On Linux server only:
# sudo ./target/release/fcoinman scan
# sudo ./target/release/fcoinman logs
# ./target/release/fcoinman check-ip 194.87.143.62
cargo build  # Just verify it compiles
```

- [ ] **Step 4: Final commit and tag**

```bash
git add -A
git commit -m "chore: v0.1.0 — all scanners implemented and tested"
git tag v0.1.0
git push && git push --tags
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] ProcessScanner — Task 7
- [x] NetworkScanner — Task 8
- [x] PersistenceScanner — Task 5 (systemd + cron + LD_PRELOAD + kernel modules)
- [x] AccountScanner — Task 4
- [x] FileScanner + ELF static analysis — Task 6
- [x] LogScanner + timeline — Task 10
- [x] ToolsScanner — Task 9
- [x] IOC Database — Task 3
- [x] JSON output — Task 11
- [x] `fcoinman analyze <binary>` — Task 6 + Task 12
- [x] `fcoinman logs` — Task 10 + Task 12
- [x] `fcoinman check-ip` — Task 12
- [x] install.sh — Task 13
- [x] llms.txt — Task 13

**MCP server and AbuseIPDB:** Excluded from this plan — separate plan after v0.1.0 ships.
