//! Compliance end-to-end against the real SBF bytecode (milestone 7):
//! the deposit-screening hook and viewing-key selective disclosure.
//!
//! Run (after `cargo build-sbf --manifest-path program/Cargo.toml`):
//! `cargo run --release --manifest-path bench/Cargo.toml --bin compliance`.

use litesvm::LiteSVM;
use mirror_pool_circuit::prover::setup;
use mirror_pool_circuit::solana::vk_to_solana;
use mirror_pool_circuit::Fr;
use mirror_pool_common::compliance::{
    open_disclosure, seal_disclosure, verify_disclosure, ViewingKeypair,
};
use mirror_pool_common::poseidon::{commitment, nullifier_hash};
use mirror_pool_common::{fr_to_bytes_be, TREE_DEPTH};
use rand::rngs::StdRng;
use rand::SeedableRng;
use solana_address::Address;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::path::PathBuf;
use std::process::exit;

const POOL_SEED: &[u8] = b"pool";
const VIEWING_SEED: &[u8] = b"viewing";
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

fn submit(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<(), String> {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|f| format!("{:?}", f.err))
}

fn submit_signed(
    svm: &mut LiteSVM,
    payer: &Keypair,
    extra: &Keypair,
    ix: Instruction,
) -> Result<(), String> {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer, extra]).unwrap();
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|f| format!("{:?}", f.err))
}

fn main() {
    let elf = std::fs::read(program_so()).unwrap_or_else(|e| {
        eprintln!("cannot read program .so: {e} (run cargo build-sbf first)");
        exit(2);
    });

    let mut rng = StdRng::seed_from_u64(0x5EED_0007);
    let (_pk, vk) = setup(TREE_DEPTH, &mut rng).expect("setup");
    let vk_bytes = vk_to_solana(&vk).to_bytes();

    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (pool, _b) =
        Address::find_program_address(&[POOL_SEED, payer.pubkey().as_ref()], &program_id);

    // Initialize (k_min = 1; this scenario exercises deposits/disclosure, not actions).
    let mut init = vec![0u8, TREE_DEPTH as u8];
    init.extend_from_slice(&1u64.to_le_bytes());
    init.extend_from_slice(&vk_bytes);
    init.extend_from_slice(&0u64.to_le_bytes()); // entry_fee = 0
    submit(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: init,
        },
    )
    .expect("initialize");

    // --- Deposit-screening hook ---
    let screener = Keypair::new();
    svm.airdrop(&screener.pubkey(), 1_000_000_000).unwrap();
    // Enable screening (variant 7).
    let mut set = vec![6u8];
    set.extend_from_slice(screener.pubkey().as_ref());
    submit(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            data: set,
        },
    )
    .expect("set screening authority");

    let secret = Fr::from(0xC0FFEEu64);
    let c = commitment(secret);
    let mut dep = vec![1u8];
    dep.extend_from_slice(&fr_to_bytes_be(&c));

    // Deposit WITHOUT the screener → must be rejected (ScreeningRequired = 24).
    let unscreened = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(pool, false)],
        data: dep.clone(),
    };
    match submit(&mut svm, &payer, unscreened) {
        Ok(()) => {
            eprintln!("FAIL: unscreened deposit accepted");
            exit(1);
        }
        Err(e) if e.contains("Custom(24)") => {
            println!("[screening] unscreened deposit correctly rejected")
        }
        Err(e) => {
            eprintln!("FAIL: unexpected rejection: {e}");
            exit(1);
        }
    }

    // Deposit WITH the screener co-signing → accepted.
    let screened = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(screener.pubkey(), true),
        ],
        data: dep,
    };
    submit_signed(&mut svm, &payer, &screener, screened).expect("screened deposit");
    println!("[screening] screened deposit accepted");

    // --- Viewing-key selective disclosure ---
    let auditor = ViewingKeypair::generate(&mut rng);
    let sealed = seal_disclosure(secret, &auditor.public_bytes(), &mut rng);
    let (record_pda, _rb) =
        Address::find_program_address(&[VIEWING_SEED, &fr_to_bytes_be(&c)], &program_id);

    // RegisterViewingKey (variant 8): commitment || auditor || vec(sealed).
    let mut data = vec![7u8];
    data.extend_from_slice(&fr_to_bytes_be(&c));
    data.extend_from_slice(&auditor.public_bytes());
    data.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
    data.extend_from_slice(&sealed);
    submit(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(record_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data,
        },
    )
    .expect("register viewing key");
    println!("[disclosure] viewing-key record registered on-chain");

    // The auditor reads the on-chain record and opens the disclosure.
    let acct = svm.get_account(&record_pda).expect("record account");
    // Layout: commitment(32) || auditor(32) || len(4 LE) || sealed.
    let stored_commitment = &acct.data[0..32];
    let stored_auditor = &acct.data[32..64];
    let slen = u32::from_le_bytes(acct.data[64..68].try_into().unwrap()) as usize;
    let stored_sealed = &acct.data[68..68 + slen];
    assert_eq!(stored_commitment, fr_to_bytes_be(&c));
    assert_eq!(stored_auditor, auditor.public_bytes());

    let recovered = open_disclosure(stored_sealed, &auditor).expect("auditor opens disclosure");
    assert_eq!(recovered, secret, "auditor recovers the member's secret");

    // The auditor attributes the member's on-chain action for some epoch.
    let epoch = 3u64;
    let nh = fr_to_bytes_be(&nullifier_hash(secret, Fr::from(epoch)));
    verify_disclosure(recovered, epoch, &nh).expect("auditor attributes the nullifier");

    // A different auditor cannot open the same record.
    let stranger = ViewingKeypair::generate(&mut rng);
    assert!(open_disclosure(stored_sealed, &stranger).is_err());

    println!("[disclosure] auditor recovered the secret and attributed the nullifier; stranger could not");
    println!("\n=== compliance PASS: screening hook enforced; selective disclosure works ===");
}
