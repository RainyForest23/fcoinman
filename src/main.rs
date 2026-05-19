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
    logs::{LogScanner, print_timeline, print_summary},
    network::NetworkScanner,
    persistence::PersistenceScanner,
    process::ProcessScanner,
    tools::ToolsScanner,
};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { json } => run_scan(json),
        Commands::Logs           => print_timeline(),
        Commands::Analyze { path } => scanner::files::analyze_binary(&path),
        Commands::CheckIp { ip }   => check_ip(&ip),
        Commands::Summary          => print_summary(),
        Commands::Update           => do_update(),
    }
}

fn run_scan(json: bool) {
    let scanners: Vec<(&str, Box<dyn Scanner>)> = vec![
        ("accounts",    Box::new(AccountScanner)),
        ("persistence", Box::new(PersistenceScanner::new(IocDatabase::load()))),
        ("files",       Box::new(FileScanner::new(IocDatabase::load()))),
        ("process",     Box::new(ProcessScanner::new(IocDatabase::load()))),
        ("network",     Box::new(NetworkScanner::new(IocDatabase::load()))),
        ("tools",       Box::new(ToolsScanner::new(IocDatabase::load()))),
        ("logs",        Box::new(LogScanner)),
    ];

    let count = scanners.len();

    let mut findings: Vec<finding::Finding> = scanners
        .iter()
        .flat_map(|(_, s)| s.scan())
        .collect();

    // Sort: Critical → Warning → Info
    findings.sort_by_key(|f| match f.severity {
        finding::Severity::Critical => 0,
        finding::Severity::Warning  => 1,
        finding::Severity::Info     => 2,
    });

    if json {
        report::json::print_json(&findings);
    } else {
        report::print_findings(&findings, count);
    }
}

fn do_update() {
    const REPO: &str = "RainyForest23/fcoinman";
    const CURRENT: &str = env!("CARGO_PKG_VERSION");

    // Detect architecture
    let arch = std::process::Command::new("uname")
        .arg("-m")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let target = match arch.as_str() {
        "x86_64"          => "x86_64-linux",
        "aarch64"|"armv7l"=> "aarch64-linux",
        other => {
            eprintln!("Unsupported architecture: {}", other);
            std::process::exit(1);
        }
    };

    // Fetch latest release tag via GitHub API
    println!("[*] Checking for updates (current: v{})...", CURRENT);
    let api_output = std::process::Command::new("curl")
        .args(["-fsSL", &format!("https://api.github.com/repos/{}/releases/latest", REPO)])
        .output();
    let json = match api_output {
        Ok(o) if !o.stdout.is_empty() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            eprintln!("[!] Could not reach GitHub API. Check your internet connection.");
            std::process::exit(1);
        }
    };

    // Parse "tag_name": "v0.1.7"
    let latest = json.lines()
        .find(|l| l.contains("\"tag_name\""))
        .and_then(|l| l.split('"').nth(3))
        .unwrap_or("")
        .trim_start_matches('v')
        .to_string();

    if latest.is_empty() {
        eprintln!("[!] Could not parse latest release tag.");
        std::process::exit(1);
    }

    if latest == CURRENT {
        println!("[✓] Already up to date (v{})", CURRENT);
        return;
    }

    println!("[*] New version available: v{} → v{}", CURRENT, latest);

    // Download to a temp file
    let url = format!(
        "https://github.com/{}/releases/download/v{}/fcoinman-{}",
        REPO, latest, target
    );
    let tmp = "/tmp/fcoinman_update";
    println!("[*] Downloading {}...", url);
    let dl = std::process::Command::new("curl")
        .args(["-fsSL", &url, "-o", tmp])
        .status();
    if !matches!(dl, Ok(s) if s.success()) {
        eprintln!("[!] Download failed. Check the URL: {}", url);
        std::process::exit(1);
    }

    // Find where the current binary lives
    let self_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/local/bin/fcoinman"));

    // chmod +x then atomic rename
    let _ = std::process::Command::new("chmod").args(["+x", tmp]).status();
    match std::fs::rename(tmp, &self_path) {
        Ok(_) => println!("[✓] Updated to v{}  ({})", latest, self_path.display()),
        Err(e) => {
            eprintln!("[!] Could not replace binary: {}", e);
            eprintln!("    Try: sudo mv {} {}", tmp, self_path.display());
            std::process::exit(1);
        }
    }
}

fn check_ip(ip: &str) {
    let ioc = IocDatabase::load();
    if ioc.is_mining_pool_ip(ip) {
        println!("[CRITICAL] {} is a known XMRig mining pool IP", ip);
    } else if ioc.irc_ports.iter().any(|_| false) {
        // port check is separate — IP lookup only here
        println!("[WARNING]  {} is not in known-bad list but verify with threat intel", ip);
    } else {
        println!("[CLEAN]    {} is not in the known-bad IP list", ip);
    }
}
