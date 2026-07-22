//! `mirror-pool-relayer` — submit `execute_action` jobs as the fee payer.
//!
//! The relayer is **core, not optional**: it pays the transaction fee so a
//! member's wallet never appears on the action they triggered (SPEC §4.4).
//!
//! * `relay`  — submit a single job file.
//! * `batch`  — submit every `*.job` in a directory, clustered into the current
//!   epoch window to maximize the per-window anonymity set (the epoch batcher).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mirror_pool_relayer::{pool_pda, relay, RelayJob};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "mirror-pool-relayer",
    about = "Fee-paying relayer for mirror-pool"
)]
struct Cli {
    /// RPC endpoint (e.g. http://127.0.0.1:8899 or a devnet URL).
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,
    /// Relayer keypair (the fee payer) — a Solana CLI keypair JSON file.
    #[arg(long)]
    keypair: PathBuf,
    /// The deployed mirror-pool program id.
    #[arg(long)]
    program_id: String,
    /// The pool authority (used to derive the pool config PDA).
    #[arg(long)]
    pool_authority: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Submit a single relay job.
    Relay {
        /// Path to a `.job` file produced by the CLI `prove` command.
        #[arg(long)]
        job: PathBuf,
    },
    /// Submit every `*.job` in a directory within one epoch window.
    Batch {
        /// Directory of `.job` files.
        #[arg(long)]
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new_with_commitment(cli.rpc_url.clone(), CommitmentConfig::confirmed());
    let relayer = read_keypair_file(&cli.keypair)
        .map_err(|e| anyhow::anyhow!("read keypair {}: {e}", cli.keypair.display()))?;
    let program_id = Pubkey::from_str(&cli.program_id).context("parse program id")?;
    let authority = Pubkey::from_str(&cli.pool_authority).context("parse pool authority")?;
    let pool = pool_pda(&program_id, &authority);

    match cli.command {
        Command::Relay { job } => {
            let job = RelayJob::load(&job)?;
            let sig = relay(&rpc, &relayer, &program_id, &pool, &job)?;
            println!("relayed: {sig}");
        }
        Command::Batch { dir } => {
            let mut jobs = Vec::new();
            for entry in std::fs::read_dir(&dir).context("read job dir")? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("job") {
                    jobs.push(path);
                }
            }
            jobs.sort();
            println!(
                "epoch batcher: submitting {} action(s) — the per-window anonymity set",
                jobs.len()
            );
            let mut ok = 0usize;
            for path in &jobs {
                let job = RelayJob::load(path)?;
                match relay(&rpc, &relayer, &program_id, &pool, &job) {
                    Ok(sig) => {
                        ok += 1;
                        println!("  {} -> {sig}", path.display());
                    }
                    Err(e) => eprintln!("  {} FAILED: {e}", path.display()),
                }
            }
            println!(
                "relayed {ok}/{} jobs (fee payer: {})",
                jobs.len(),
                relayer.pubkey()
            );
        }
    }
    Ok(())
}
