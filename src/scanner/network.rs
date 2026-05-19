use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;
use std::net::Ipv4Addr;

pub struct NetworkScanner {
    pub ioc: IocDatabase,
}

impl NetworkScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for NetworkScanner {

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for proc_file in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = fs::read_to_string(proc_file) {
                findings.extend(scan_connections(&content, &self.ioc));
            }
        }
        findings
    }
}

// ── /proc/net/tcp parsing ────────────────────────────────────────────────────
//
// Format: sl local_addr rem_addr st tx_queue rx_queue tr tm->when retrnsmt uid ...
// Addresses are hex little-endian: AABBCCDD:PPPP
// State 01 = ESTABLISHED

struct TcpEntry {
    remote_ip: String,
    remote_port: u16,
    state: u8,
}

/// Parses a little-endian hex IPv4 from /proc/net/tcp (e.g. "3E8F57C2" → "194.87.143.62")
pub fn parse_hex_ip(hex: &str) -> Option<String> {
    if hex.len() != 8 { return None; }
    let n = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/tcp stores IPs in host byte order on little-endian machines,
    // which means the bytes are reversed relative to the dotted notation.
    let bytes = n.to_le_bytes(); // [194, 87, 143, 62] for "3E8F57C2"
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
}

pub fn parse_hex_port(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

fn parse_entries(content: &str) -> Vec<TcpEntry> {
    content.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 { return None; }
        let remote = fields[2];
        let state_str = fields[3];
        let parts: Vec<&str> = remote.split(':').collect();
        if parts.len() != 2 { return None; }
        Some(TcpEntry {
            remote_ip:   parse_hex_ip(parts[0])?,
            remote_port: parse_hex_port(parts[1])?,
            state:       u8::from_str_radix(state_str, 16).ok()?,
        })
    }).collect()
}

fn scan_connections(content: &str, ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in parse_entries(content) {
        if entry.state != 0x01 { continue; } // only ESTABLISHED

        if ioc.is_mining_pool_ip(&entry.remote_ip) {
            findings.push(Finding::critical(
                "Active connection to known mining pool IP",
                "Established TCP connection to a known XMRig mining pool server",
                &format!("{}:{}", entry.remote_ip, entry.remote_port),
            ));
        }
        if ioc.is_mining_port(entry.remote_port) && !ioc.is_mining_pool_ip(&entry.remote_ip) {
            findings.push(Finding::warning(
                "Connection on known mining pool port",
                "Port commonly used by XMRig (3333, 4444, 5555, 5332, 14444)",
                &format!("{}:{}", entry.remote_ip, entry.remote_port),
            ));
        }
        if ioc.is_irc_port(entry.remote_port) {
            findings.push(Finding::warning(
                "Active IRC connection detected",
                "IRC (port 6667/6697/6666) is the C2 channel for Kaiten and similar botnets — verify with `ss -tnp`",
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
    fn hex_ip_parses_known_mining_pool() {
        // 194.87.143.62 in little-endian hex:
        // bytes: C2 57 8F 3E → as u32 LE = 0x3E8F57C2
        assert_eq!(parse_hex_ip("3E8F57C2"), Some("194.87.143.62".to_string()));
    }

    #[test]
    fn hex_port_parses_correctly() {
        assert_eq!(parse_hex_port("1A0B"), Some(6667));  // IRC
        assert_eq!(parse_hex_port("0D05"), Some(3333));  // mining pool
        assert_eq!(parse_hex_port("14D4"), Some(5332));  // XMRig pool from incident
    }

    #[test]
    fn established_irc_connection_flagged() {
        let ioc = IocDatabase::load();
        // Remote: 1.2.3.4:6667 (IRC), state 01 (ESTABLISHED)
        // 1.2.3.4 LE hex: 04030201
        let fake = "  sl  local_address rem_address   st\n\
                    0: 00000000:0035 04030201:1A0B 01 00000000:00000000\n";
        let findings = scan_connections(fake, &ioc);
        assert!(findings.iter().any(|f| f.title.contains("IRC")));
    }

    #[test]
    fn non_established_connection_ignored() {
        let ioc = IocDatabase::load();
        // State 0A = LISTEN — should not be flagged
        let fake = "  sl  local_address rem_address   st\n\
                    0: 00000000:1A0B 04030201:1A0B 0A 00000000:00000000\n";
        let findings = scan_connections(fake, &ioc);
        assert!(findings.is_empty());
    }

    #[test]
    fn mining_pool_ip_from_incident_flagged() {
        let ioc = IocDatabase::load();
        assert!(ioc.is_mining_pool_ip("194.87.143.62"));
        assert!(ioc.is_mining_pool_ip("8.217.191.41"));
    }
}
