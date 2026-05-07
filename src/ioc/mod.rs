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
    fn unknown_ip_not_flagged() {
        let db = IocDatabase::load();
        assert!(!db.is_mining_pool_ip("1.1.1.1"));
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

    #[test]
    fn normal_cmdline_not_flagged() {
        let db = IocDatabase::load();
        assert!(!db.has_xmrig_signature("nginx -g daemon off"));
    }
}
