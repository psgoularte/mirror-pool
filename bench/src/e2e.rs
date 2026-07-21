//! End-to-end litesvm test of `InitializePool` + `Deposit` against the actual
//! SBF bytecode: create the pool PDA, deposit commitments, then read the pool
//! account and confirm the on-chain root matches the off-chain reference tree.
//!
//! Run (after `cargo build-sbf --manifest-path program/Cargo.toml`):
//! `cargo run --release --manifest-path bench/Cargo.toml --bin e2e`.

use litesvm::LiteSVM;
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon::commitment;
use mirror_pool_common::{fr_to_bytes_be, Fr, TREE_DEPTH};
use solana_address::Address;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::path::PathBuf;
use std::process::exit;

// Offset of `current_root` within the borsh-serialized PoolConfig:
// is_initialized(1) + authority(32) + bump(1) + depth(1) + next_index(8)
// + root_history_index(8) = 51.
const CURRENT_ROOT_OFFSET: usize = 51;

const POOL_SEED: &[u8] = b"pool";
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);

fn program_so() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::env::var("MIRROR_POOL_PROGRAM_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target/deploy/mirror_pool_program.so"))
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], label: &str) {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &blockhash);
    let tx =
        VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).expect("sign tx");
    match svm.send_transaction(tx) {
        Ok(meta) => {
            println!("[{label}] ok, {} CU", meta.compute_units_consumed);
        }
        Err(failed) => {
            eprintln!("[{label}] FAILED: {:?}", failed.err);
            for l in &failed.meta.logs {
                eprintln!("  log: {l}");
            }
            exit(1);
        }
    }
}

fn main() {
    let elf = std::fs::read(program_so()).unwrap_or_else(|e| {
        eprintln!("cannot read program .so: {e} (run cargo build-sbf first)");
        exit(2);
    });

    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 5_000_000_000)
        .expect("airdrop");

    let (pool, _bump) =
        Address::find_program_address(&[POOL_SEED, payer.pubkey().as_ref()], &program_id);

    // InitializePool { depth } — borsh: variant 1, then depth u8.
    let init_data = vec![1u8, TREE_DEPTH as u8];
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data: init_data,
    };
    send(&mut svm, &payer, &[init_ix], "initialize_pool");

    // Deposit a few commitments; mirror them in the reference tree.
    let mut reference = MerkleTree::new(TREE_DEPTH);
    for i in 0..3u64 {
        let c = commitment(Fr::from(i + 1));
        reference.insert(c).unwrap();
        let mut data = vec![2u8]; // Deposit variant
        data.extend_from_slice(&fr_to_bytes_be(&c));
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pool, false)],
            data,
        };
        send(&mut svm, &payer, &[ix], &format!("deposit[{i}]"));
    }

    // Read the pool account and compare the on-chain root to the reference.
    let account = svm.get_account(&pool).expect("pool account exists");
    let onchain_root = &account.data[CURRENT_ROOT_OFFSET..CURRENT_ROOT_OFFSET + 32];
    let expected = fr_to_bytes_be(&reference.root());

    if onchain_root == expected.as_slice() {
        println!("\n=== e2e PASS: on-chain root matches reference after 3 deposits ===");
    } else {
        eprintln!("\n=== e2e FAIL: root mismatch ===");
        eprintln!("on-chain: {}", hex(onchain_root));
        eprintln!("expected: {}", hex(&expected));
        exit(1);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
