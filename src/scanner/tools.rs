use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub struct ToolsScanner {
    pub ioc: IocDatabase,
}

impl ToolsScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for ToolsScanner {

    fn scan(&self) -> Vec<Finding> {
        check_attacker_tools(&self.ioc)
    }
}

fn check_attacker_tools(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let seven_days = 7 * 86400u64;

    let search_paths = [
        "/usr/bin", "/usr/local/bin", "/usr/sbin",
        "/tmp", "/var/bin", "/dev/shm",
    ];

    for tool in &ioc.attacker_tools {
        for dir in &search_paths {
            let path = Path::new(dir).join(tool);
            if !path.exists() { continue; }

            let in_suspicious_dir = ioc.is_suspicious_path(dir);

            let age_secs = fs::metadata(&path)
                .and_then(|m| m.modified())
                .and_then(|t| SystemTime::now().duration_since(t)
                    .map_err(|_| std::io::Error::other("")))
                .map(|d| d.as_secs())
                .unwrap_or(u64::MAX);

            if in_suspicious_dir {
                findings.push(Finding::critical(
                    "Offensive tool in suspicious directory",
                    "Attacker-used tool found outside standard system paths",
                    &format!("{}", path.display()),
                ));
            } else if age_secs < seven_days {
                findings.push(Finding::warning(
                    "Recently installed offensive tool",
                    "Tool installed within last 7 days — verify this was intentional",
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
    fn attacker_tools_list_populated() {
        let ioc = IocDatabase::load();
        assert!(ioc.attacker_tools.contains(&"masscan".to_string()));
        assert!(ioc.attacker_tools.contains(&"hydra".to_string()));
        assert!(ioc.attacker_tools.contains(&"xmrig".to_string()));
    }

    #[test]
    fn tool_in_tmp_is_suspicious() {
        let ioc = IocDatabase::load();
        assert!(ioc.is_suspicious_path("/tmp/masscan"));
        assert!(ioc.is_suspicious_path("/dev/shm/hydra"));
    }

    #[test]
    fn tool_in_standard_path_not_suspicious_dir() {
        let ioc = IocDatabase::load();
        assert!(!ioc.is_suspicious_path("/usr/bin/nmap"));
    }
}
