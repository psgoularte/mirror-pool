//! Full-flow end-to-end test against the actual SBF bytecode (milestone 5):
//! initialize a pool (with a real verifying key) → deposit member commitments →
//! prove membership → `execute_action` (no-op) → confirm the nullifier is spent
//! by replaying and expecting rejection.
//!
//! This exercises the entire core protocol path with genuine cryptography.
//! Run (after `cargo build-sbf --manifest-path program/Cargo.toml`):
//! `cargo run --release --manifest-path bench/Cargo.toml --bin flow`.

use litesvm::LiteSVM;
use mirror_pool_circuit::prover::{build_witness, prove, setup};
use mirror_pool_circuit::solana::{proof_to_solana, vk_to_solana};
use mirror_pool_circuit::Fr;
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon::{action_binding, commitment};
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
const NULLIFIER_SEED: &[u8] = b"nullifier";
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);
const SELECTOR_NOOP: u8 = 0;

fn program_so() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::env::var("MIRROR_POOL_PROGRAM_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target/deploy/mirror_pool_program.so"))
}

/// Send a transaction; return Ok/Err with logs printed under `label`.
fn try_send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction, label: &str) -> Result<u64, ()> {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
    match svm.send_transaction(tx) {
        Ok(meta) => {
            println!("[{label}] ok, {} CU", meta.compute_units_consumed);
            Ok(meta.compute_units_consumed)
        }
        Err(failed) => {
            println!("[{label}] rejected: {:?}", failed.err);
            Err(())
        }
    }
}

fn main() {
    let elf = std::fs::read(program_so()).unwrap_or_else(|e| {
        eprintln!("cannot read program .so: {e} (run cargo build-sbf first)");
        exit(2);
    });

    // --- Trusted setup + verifying key bytes for on-chain. ---
    let mut rng = StdRng::seed_from_u64(0x5EED_0005);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).expect("setup");
    let vk_bytes = vk_to_solana(&vk).to_bytes();
    assert_eq!(vk_bytes.len(), 769, "expected VK_SERIALIZED_LEN");

    // --- litesvm + program. ---
    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("airdrop");
    let (pool, _bump) =
        Address::find_program_address(&[POOL_SEED, payer.pubkey().as_ref()], &program_id);

    // --- InitializePool { depth, verifying_key }  (borsh variant 1). ---
    let mut init_data = vec![1u8, TREE_DEPTH as u8];
    init_data.extend_from_slice(&vk_bytes);
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data: init_data,
    };
    if try_send(&mut svm, &payer, init_ix, "initialize_pool").is_err() {
        exit(1);
    }

    // --- Deposit member commitments; mirror off-chain to build the witness. ---
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut secrets = Vec::new();
    for i in 0..4u64 {
        let secret = Fr::from(1000 + i);
        let c = commitment(secret);
        tree.insert(c).unwrap();
        secrets.push(secret);
        let mut data = vec![2u8]; // Deposit
        data.extend_from_slice(&fr_to_bytes_be(&c));
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pool, false)],
            data,
        };
        if try_send(&mut svm, &payer, ix, &format!("deposit[{i}]")).is_err() {
            exit(1);
        }
    }

    // A closure that proves membership for `member` at `epoch` bound to
    // `selector`, returning (256-byte proof, 4 public-input limbs).
    let mut prove_member = |member: usize, epoch: u64, selector: u8| {
        let binding = action_binding(selector);
        let path = tree.proof(member).unwrap();
        let assignment = build_witness(secrets[member], &path, Fr::from(epoch), binding).unwrap();
        let pi = assignment.public_inputs.to_bytes();
        let sol_proof =
            proof_to_solana(&prove(&pk, assignment.circuit, &mut rng).unwrap()).to_bytes();
        let mut proof = [0u8; 256];
        proof.copy_from_slice(&sol_proof);
        let mut limbs = [[0u8; 32]; 4];
        for (i, l) in pi.iter().enumerate() {
            limbs[i] = *l;
        }
        (proof, limbs)
    };

    // Happy path: member #2, epoch 0, no-op.
    let (proof, pi) = prove_member(2, 0, SELECTOR_NOOP);
    let ok_ix = exec_ix(program_id, pool, &proof, &pi, SELECTOR_NOOP, payer.pubkey());
    if try_send(&mut svm, &payer, ok_ix, "execute_action").is_err() {
        eprintln!("FAIL: valid proof was rejected");
        exit(1);
    }

    // Replay: same nullifier, DIFFERENT fee payer (so it is not deduped as an
    // already-processed transaction) — must be rejected by the program.
    let relayer2 = Keypair::new();
    svm.airdrop(&relayer2.pubkey(), 1_000_000_000)
        .expect("airdrop2");
    let replay = exec_ix(
        program_id,
        pool,
        &proof,
        &pi,
        SELECTOR_NOOP,
        relayer2.pubkey(),
    );
    expect_reject(&mut svm, &relayer2, replay, "replay (spent nullifier)", 16);

    // Action-binding mismatch: send member #2's proof but claim selector 1.
    let mismatch = exec_ix(program_id, pool, &proof, &pi, 1, payer.pubkey());
    expect_reject(&mut svm, &payer, mismatch, "action-binding mismatch", 15);

    // Tampered proof (fresh member #3 so the nullifier is not the blocker).
    let (mut bad_proof, pi3) = prove_member(3, 0, SELECTOR_NOOP);
    bad_proof[0] ^= 0x01;
    let tampered = exec_ix(
        program_id,
        pool,
        &bad_proof,
        &pi3,
        SELECTOR_NOOP,
        payer.pubkey(),
    );
    // Rejection may surface as InvalidProof (2) at construction or
    // ProofVerificationFailed (3) at the pairing — either is a rejection.
    expect_reject_any(&mut svm, &payer, tampered, "tampered proof", &[2, 3]);

    // Wrong epoch: prove against epoch 1 while the pool is at epoch 0.
    let (proof_e1, pi_e1) = prove_member(1, 1, SELECTOR_NOOP);
    let wrong_epoch = exec_ix(
        program_id,
        pool,
        &proof_e1,
        &pi_e1,
        SELECTOR_NOOP,
        payer.pubkey(),
    );
    expect_reject(&mut svm, &payer, wrong_epoch, "wrong epoch", 14);

    println!("\n=== flow PASS: valid action ran via PDA; replay, binding, tampered proof, and wrong epoch all rejected ===");
}

/// Build an `ExecuteAction` instruction (borsh variant 3).
fn exec_ix(
    program_id: Address,
    pool: Address,
    proof: &[u8; 256],
    pi: &[[u8; 32]; 4],
    selector: u8,
    fee_payer: Address,
) -> Instruction {
    let (nullifier_pda, _b) = Address::find_program_address(&[NULLIFIER_SEED, &pi[1]], &program_id);
    let mut data = vec![3u8];
    data.extend_from_slice(proof);
    for limb in pi {
        data.extend_from_slice(limb);
    }
    data.push(selector);
    data.extend_from_slice(&0u32.to_le_bytes()); // empty params vec
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(fee_payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(program_id, false), // CPI target (self)
        ],
        data,
    }
}

fn expect_reject(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction, label: &str, code: u32) {
    expect_reject_any(svm, payer, ix, label, &[code]);
}

/// Assert the transaction is rejected with a `Custom(code)` in `codes`.
fn expect_reject_any(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ix: Instruction,
    label: &str,
    codes: &[u32],
) {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => {
            eprintln!("FAIL[{label}]: expected rejection, but the tx succeeded");
            exit(1);
        }
        Err(failed) => {
            let s = format!("{:?}", failed.err);
            let matched = codes.iter().any(|c| s.contains(&format!("Custom({c})")));
            if matched {
                println!("[{label}] correctly rejected: {s}");
            } else {
                eprintln!("FAIL[{label}]: rejected but not with Custom{codes:?}: {s}");
                exit(1);
            }
        }
    }
}
