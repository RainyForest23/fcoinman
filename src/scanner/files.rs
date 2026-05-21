use crate::finding::Finding;
use crate::ioc::IocDatabase;
use crate::scanner::Scanner;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct FileScanner {
    pub ioc: IocDatabase,
}

impl FileScanner {
    pub fn new(ioc: IocDatabase) -> Self { Self { ioc } }
}

impl Scanner for FileScanner {

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_suspicious_paths(&self.ioc));
        findings.extend(scan_system_binary_hashes(&self.ioc));
        findings
    }
}

// ── Hash ────────────────────────────────────────────────────────────────────

pub fn sha256_file(path: &Path) -> Option<String> {
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

// ── ELF helpers ─────────────────────────────────────────────────────────────

pub fn is_elf(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map(|_| magic == [0x7f, b'E', b'L', b'F'])
        .unwrap_or(false)
}

/// Returns true if the binary has NO .symtab section (symbols stripped).
pub fn is_stripped(path: &Path) -> bool {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return true,
    };
    !content.windows(7).any(|w| w == b".symtab")
}

/// Extract printable ASCII strings ≥8 chars and match against IOC signatures.
pub fn extract_ioc_strings(path: &Path, ioc: &IocDatabase) -> Vec<String> {
    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut matches = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &byte in &content {
        if (0x20..0x7f).contains(&byte) {
            current.push(byte);
        } else {
            if current.len() >= 8 {
                let s = String::from_utf8_lossy(&current).to_string();
                let first_word = s.split_whitespace().next().unwrap_or("");
                if ioc.has_xmrig_signature(&s)
                    || ioc.mining_pool_ips.iter().any(|ip| s.contains(ip.as_str()))
                    || s.contains("stratum+")
                    || s.contains("PRIVMSG")
                    || first_word == "OPER"
                    || s.contains("JOIN #")
                {
                    matches.push(s);
                }
            }
            current.clear();
        }
    }
    matches
}

// ── Scan functions ───────────────────────────────────────────────────────────

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn scan_suspicious_paths(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    for dir in &ioc.suspicious_paths {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || !is_executable(&path) { continue; }

            findings.push(Finding::warning(
                "Executable file in suspicious directory",
                "Attackers stage malware in /tmp, /dev/shm, /var/bin — these dirs should not contain executables",
                &format!("{}", path.display()),
            ));

            if let Some(hash) = sha256_file(&path) {
                if ioc.is_bad_hash(&hash) {
                    findings.push(Finding::critical(
                        "Known malware binary detected (hash match)",
                        "File SHA-256 matches a known XMRig or Kaiten binary",
                        &format!("{} sha256:{}", path.display(), hash),
                    ));
                }
            }
        }
    }
    findings
}

// scan_recent_system_binaries removed — fires on every apt upgrade and fresh install,
// producing only noise. Tampering is detected more accurately by hash matching and
// IOC string extraction in scan_system_binary_hashes().

fn scan_system_binary_hashes(ioc: &IocDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    for dir in &["/usr/bin", "/usr/sbin"] {
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
                        "Known malware binary in system path (hash match)",
                        "System binary matches SHA-256 of known XMRig or Kaiten malware",
                        &format!("{} sha256:{}", path.display(), hash),
                    ));
                }
            }

            let hits = extract_ioc_strings(&path, ioc);
            if !hits.is_empty() {
                findings.push(Finding::critical(
                    "Malware IOC strings found inside system binary",
                    "Binary contains mining pool addresses, IRC commands, or miner CLI flags",
                    &format!("{}: {:?}", path.display(), &hits[..hits.len().min(3)]),
                ));
            }
        }
    }
    findings
}

// ── Public helper for `fcoinman analyze <path>` ──────────────────────────────

pub fn analyze_binary(path: &str) {
    let ioc = IocDatabase::load();
    let p = Path::new(path);

    if !p.exists() {
        eprintln!("File not found: {}", path);
        return;
    }

    println!("\n[Binary Analysis] {}\n", path);

    if is_elf(p) {
        println!("  [✓] ELF binary confirmed");
    } else {
        println!("  [!] Not an ELF binary");
    }

    if is_stripped(p) {
        println!("  [!] STRIPPED — debug symbols removed (harder to analyze)");
    } else {
        println!("  [✓] NOT stripped — function names are visible in Ghidra/IDA");
    }

    if let Some(hash) = sha256_file(p) {
        println!("  SHA-256: {}", hash);
        if ioc.is_bad_hash(&hash) {
            println!("  [CRITICAL] Hash matches known malware (XMRig or Kaiten)!");
        } else {
            println!("  [✓] Hash not in known-bad list");
        }
    }

    let hits = extract_ioc_strings(p, &ioc);
    if hits.is_empty() {
        println!("  [✓] No suspicious strings found");
    } else {
        println!("  [!] Suspicious strings detected:");
        for s in &hits {
            println!("      → {}", s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_elf_not_flagged_as_elf() {
        let path = "/tmp/fcoinman_test_notelf.txt";
        std::fs::write(path, "hello world plain text").unwrap();
        assert!(!is_elf(Path::new(path)));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sha256_is_deterministic() {
        let path = "/tmp/fcoinman_test_hash.bin";
        std::fs::write(path, b"deterministic content 12345").unwrap();
        let h1 = sha256_file(Path::new(path)).unwrap();
        let h2 = sha256_file(Path::new(path)).unwrap();
        assert_eq!(h1, h2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sha256_differs_for_different_content() {
        let p1 = "/tmp/fcoinman_hash_a.bin";
        let p2 = "/tmp/fcoinman_hash_b.bin";
        std::fs::write(p1, b"content A").unwrap();
        std::fs::write(p2, b"content B").unwrap();
        let h1 = sha256_file(Path::new(p1)).unwrap();
        let h2 = sha256_file(Path::new(p2)).unwrap();
        assert_ne!(h1, h2);
        std::fs::remove_file(p1).unwrap();
        std::fs::remove_file(p2).unwrap();
    }

    #[test]
    fn ioc_string_extraction_finds_stratum() {
        let ioc = IocDatabase::load();
        let path = "/tmp/fcoinman_test_strings.bin";
        // Pad with nulls around the string so it gets extracted
        let mut content = vec![0u8; 16];
        content.extend_from_slice(b"stratum+tcp://pool.minexmr.com");
        content.extend_from_slice(&[0u8; 16]);
        std::fs::write(path, &content).unwrap();
        let hits = extract_ioc_strings(Path::new(path), &ioc);
        assert!(!hits.is_empty(), "Should find stratum+tcp:// IOC string");
        std::fs::remove_file(path).unwrap();
    }
}
