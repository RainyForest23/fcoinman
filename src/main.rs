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
    logs::{LogScanner, print_timeline},
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
    }
}

fn run_scan(json: bool) {
    let scanners: Vec<(&str, Box<dyn Scanner>)> = vec![
        ("accounts",    Box::new(AccountScanner)),
        ("persistence", Box::new(PersistenceScanner)),
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
