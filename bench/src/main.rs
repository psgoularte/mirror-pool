//! Compute-unit benchmark for on-chain membership verification (SPEC §7:
//! "benchmark execute_action compute units; keep verification under ~200k").
//!
//! Runs the **actual SBF bytecode** in litesvm over a real membership proof and
//! reports the compute units consumed by the `VerifyMembership` instruction.
//!
//! Inputs (both produced by the workspace):
//! * the program artifact `target/deploy/mirror_pool_program.so`
//!   (`cargo build-sbf --manifest-path program/Cargo.toml`), and
//! * the fixture `target/mirror-pool-cu-fixture.bin`
//!   (`cargo test -p mirror-pool-program --test gen_fixture -- --ignored`).
//!
//! Run: `cargo run --release --manifest-path bench/Cargo.toml`. Exits non-zero
//! if verification fails or exceeds the budget.

use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::path::PathBuf;
use std::process::exit;

/// Compute-unit ceiling from the SPEC.
const CU_BUDGET: u64 = 200_000;

fn repo_root() -> PathBuf {
    // bench/ is one level below the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bench crate has a parent dir")
        .to_path_buf()
}

fn read_len_prefixed(buf: &[u8], off: &mut usize) -> Vec<u8> {
    let len = u32::from_le_bytes(buf[*off..*off + 4].try_into().expect("len prefix")) as usize;
    *off += 4;
    let out = buf[*off..*off + len].to_vec();
    *off += len;
    out
}

fn main() {
    let root = repo_root();
    let so_path = std::env::var("MIRROR_POOL_PROGRAM_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target/deploy/mirror_pool_program.so"));
    let fixture_path = std::env::var("MIRROR_POOL_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target/mirror-pool-cu-fixture.bin"));

    let elf = std::fs::read(&so_path).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot read program artifact {}: {e}\n\
             build it first: cargo build-sbf --manifest-path program/Cargo.toml",
            so_path.display()
        );
        exit(2);
    });
    let fixture = std::fs::read(&fixture_path).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot read fixture {}: {e}\n\
             generate it first: cargo test -p mirror-pool-program --test gen_fixture -- --ignored",
            fixture_path.display()
        );
        exit(2);
    });

    let mut off = 0usize;
    let vk_bytes = read_len_prefixed(&fixture, &mut off);
    let instruction_data = read_len_prefixed(&fixture, &mut off);

    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("airdrop");

    let vk_addr = Address::new_unique();
    svm.set_account(
        vk_addr,
        Account {
            lamports: 1_000_000_000,
            data: vk_bytes,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set vk account");

    // Raise the CU limit so we measure the true cost rather than aborting at the
    // default per-instruction cap.
    let raise_limit = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let verify_ix = Instruction {
        program_id,
        accounts: vec![AccountMeta {
            pubkey: vk_addr,
            is_signer: false,
            is_writable: false,
        }],
        data: instruction_data,
    };

    let blockhash = svm.latest_blockhash();
    let msg =
        Message::new_with_blockhash(&[raise_limit, verify_ix], Some(&payer.pubkey()), &blockhash);
    let tx =
        VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).expect("sign tx");

    match svm.send_transaction(tx) {
        Ok(meta) => {
            let cu = meta.compute_units_consumed;
            for line in &meta.logs {
                println!("log: {line}");
            }
            println!("\n=== mirror-pool VerifyMembership: {cu} CU (budget {CU_BUDGET}) ===");
            if cu >= CU_BUDGET {
                eprintln!("FAIL: {cu} CU exceeds the {CU_BUDGET} budget");
                exit(1);
            }
            println!("PASS: within budget");
        }
        Err(failed) => {
            eprintln!("FAIL: VerifyMembership transaction did not succeed");
            for line in &failed.meta.logs {
                eprintln!("log: {line}");
            }
            eprintln!("error: {:?}", failed.err);
            exit(1);
        }
    }
}
