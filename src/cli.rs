use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fcoinman",
    about = "Linux server compromise detector\nBased on a real XMRig + Kaiten IRC bot infection via SSH brute force.\nRun as root for full results.",
    version,
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run full compromise scan — checks processes, network, files, accounts, logs
    Scan {
        /// Output results as machine-readable JSON (useful for AI tools and scripts)
        #[arg(long)]
        json: bool,
    },

    /// Reconstruct attack timeline from system logs (auth.log)
    Logs,

    /// Analyze a specific binary for malware signatures (ELF, strings, hash)
    Analyze {
        /// Path to the binary to analyze
        path: String,
    },

    /// Check if an IP address is a known mining pool or C2 server
    CheckIp {
        /// IP address to look up
        ip: String,
    },
}
