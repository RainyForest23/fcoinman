# servershield — Design Spec
**Date:** 2026-05-07  
**Status:** Draft

---

## Background & Motivation

This tool was designed based on a real incident: an Alienware Aurora R12 (Ubuntu 22.04) server was compromised via SSH brute force (password: "password"). The attacker installed:
- **XMRig** cryptominer disguised as `/usr/bin/socket` — consumed 847% CPU + 2x RTX 3060 GPU
- **Kaiten IRC bot** disguised as `/usr/bin/zsd` — persisted via systemd, connected to IRC C2
- **Backdoor UID-0 account** (`system:x:0:1001`)
- **SSH authorized_keys backdoor**

No existing open-source tool would have clearly detected this combination. `servershield` fills that gap.

---

## Goal

A CLI tool that answers one question: **"Is my Linux server currently compromised?"**

Target user: individual developers/students who run personal Linux servers and notice something suspicious (high CPU, loud fans, unknown processes).

---

## Non-Goals

- Not an enterprise EDR/SIEM
- No real-time daemon (v1)
- No automatic remediation (detection only)
- No Windows/macOS support

---

## Architecture

### Language & Distribution

- **Language:** Rust
- **Distribution:** Single static binary
- **Installation:** `curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash`
- **Runtime deps:** None (statically linked)
- **Minimum OS:** Ubuntu 20.04+ / Debian 11+ (any Linux with `/proc`)

### Crate Dependencies

```toml
[dependencies]
clap    = "4"     # CLI argument parsing
serde   = { version = "1", features = ["derive"] }
serde_json = "1"  # IOC database parsing
colored = "2"     # terminal color output
sha2    = "0.10"  # file hash comparison
```

### Directory Structure

```
servershield/
├── Cargo.toml
├── install.sh               ← curl installer
└── src/
    ├── main.rs              ← entry point, scanner orchestration
    ├── cli.rs               ← clap CLI definitions
    ├── finding.rs           ← Finding struct, Severity enum
    ├── scanner/
    │   ├── mod.rs           ← Scanner trait
    │   ├── process.rs       ← /proc analysis, CPU/GPU anomalies
    │   ├── network.rs       ← IRC port, mining pool IP detection
    │   ├── persistence.rs   ← systemd service anomalies
    │   ├── accounts.rs      ← UID-0 backdoors, authorized_keys
    │   └── files.rs         ← suspicious paths, known-bad hashes
    ├── ioc/
    │   ├── mod.rs           ← IOC loading + matching logic
    │   └── indicators.json  ← known mining pool IPs, bad hashes, IRC ports
    └── report.rs            ← colored terminal output, severity summary
```

---

## Core Data Model

```rust
pub enum Severity { Critical, Warning, Info }

pub struct Finding {
    pub severity:    Severity,
    pub title:       String,
    pub description: String,
    pub evidence:    String,  // actual value found (e.g. "uid=0, name=system")
}
```

```rust
pub trait Scanner {
    fn name(&self) -> &str;
    fn scan(&self) -> Vec<Finding>;
}
```

---

## Scanner Modules

### 1. `process.rs` — Process Anomaly Scanner
**What it checks:**
- Processes consuming >80% CPU sustained (via `/proc/[pid]/stat`)
- Process name vs binary path mismatch (e.g. process named `socket` but binary is not `/bin/socket`)
- Known XMRig strings in `/proc/[pid]/cmdline` (pool addresses, `--donate-level`)
- Processes running from suspicious paths: `/tmp`, `/dev/shm`, `/var/bin`

**Real incident basis:** XMRig ran as `/usr/bin/socket` consuming 847% CPU

### 2. `network.rs` — Network Connection Scanner
**What it checks:**
- Outbound connections to known mining pool IPs (from `indicators.json`)
- Connections on IRC ports: 6667, 6697, 7000
- Parse `/proc/net/tcp` and `/proc/net/tcp6` (no external command dependency)
- Correlate connection with owning PID via `/proc/net/tcp` inode → `/proc/[pid]/fd`

**Real incident basis:** XMRig connected to `194.87.143.62:5332`, `8.217.191.41:5332`

### 3. `persistence.rs` — Persistence Mechanism Scanner
**What it checks:**
- All `.service` files in `/etc/systemd/system/` and `/lib/systemd/system/`
- Services whose `ExecStart` binary path is non-standard (not in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`)
- Recently modified service files (mtime within last 30 days)
- Cron entries in `/etc/cron*` and `/var/spool/cron/`

**Real incident basis:** `socket.service` and `zsd.service` installed by attacker

### 4. `accounts.rs` — Backdoor Account Scanner
**What it checks:**
- `/etc/passwd` entries with `uid=0` other than `root`
- Recently added accounts (compare mtime of `/etc/passwd`)
- `~/.ssh/authorized_keys` for all users — flag keys with unusual comments or from unknown sources
- `/root/.ssh/authorized_keys` specifically

**Real incident basis:** `system:x:0:1001` UID-0 backdoor account, `root@root` SSH key

### 5. `files.rs` — Suspicious File Scanner
**What it checks:**
- Files in `/tmp`, `/dev/shm`, `/var/bin`, `/var/tmp` that are executable
- SHA-256 hash comparison against `indicators.json` known-bad hashes
- SUID/SGID binaries in non-standard locations
- Recently modified binaries in `/usr/bin`, `/usr/sbin` (mtime within 7 days)

**Real incident basis:** `/var/bin` directory created by attacker; `/usr/bin/socket` and `/usr/bin/zsd` replaced

---

## IOC Database (`indicators.json`)

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
  "standard_binary_paths": ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
}
```

---

## CLI Interface

```
$ sudo servershield scan

Running 5 scanners...

[CRITICAL] UID-0 backdoor account detected
           Evidence: system:x:0:1001:/root:/bin/bash

[CRITICAL] Process matches XMRig cryptominer signature
           Evidence: /usr/bin/socket (CPU: 847%, cmdline contains --donate-level)

[WARNING]  Outbound connection to known mining pool
           Evidence: 194.87.143.62:5332 (pid 1234 → /usr/bin/socket)

[WARNING]  Non-standard systemd service detected
           Evidence: socket.service → ExecStart=/usr/bin/socket

[INFO]     No suspicious authorized_keys entries found

──────────────────────────────────────────
Result: LIKELY COMPROMISED (2 critical, 2 warnings)
Recommendation: Disconnect from network immediately. Do not trust this system.
```

---

## Installation Script (`install.sh`)

```bash
#!/bin/bash
# Detects arch, downloads correct binary from GitHub Releases, places in /usr/local/bin
```

One-liner:
```bash
curl -fsSL https://raw.githubusercontent.com/[user]/servershield/main/install.sh | sudo bash
```

---

## Out of Scope (v1)

- Real-time daemon / inotify watching
- Automatic removal of malware
- Email/Slack alerting
- Container (Docker/K8s) scanning
- Non-Linux platforms

---

## Success Criteria

- `sudo servershield scan` completes in <5 seconds on a typical server
- Correctly identifies all 5 attack artifacts from the original incident
- Zero false positives on a clean Ubuntu 22.04 install
- Single binary, no runtime dependencies
- README tells the origin story (real incident → this tool)
