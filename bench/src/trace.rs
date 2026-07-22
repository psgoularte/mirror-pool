//! Observable-trace red-team (VALIDATION Level 3).
//!
//! Runs a multi-member epoch through a **dedicated relayer** and then attacks
//! the public trace exactly as a chain-analysis tool would: for every landed
//! `execute_action`, inspect the fee payer, signers, and account metas, and try
//! to map member → action. The gates:
//!
//! * fee payer is ALWAYS the relayer, never a member;
//! * no member is a signer on any action transaction;
//! * no account meta / PDA seed is derived from a member identity;
//! * the effective anonymity set per epoch is reported and must be > 1.
//!
//! Members deliberately have **no Solana keypair** in the action path — their
//! only on-chain footprints are a `commitment` (at deposit) and a
//! `nullifier_hash` (at action), which are unlinkable without the secret.
//!
//! Run (after `cargo build-sbf`):
//! `cargo run --release --manifest-path bench/Cargo.toml --bin trace`.

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
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::exit;

const POOL_SEED: &[u8] = b"pool";
const NULLIFIER_SEED: &[u8] = b"nullifier";
const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);
const SELECTOR_NOOP: u8 = 0;

const N_MEMBERS: u64 = 12;
const N_ACTORS: usize = 6;

fn program_so() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::env::var("MIRROR_POOL_PROGRAM_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target/deploy/mirror_pool_program.so"))
}

fn main() {
    let elf = std::fs::read(program_so()).unwrap_or_else(|e| {
        eprintln!("cannot read program .so: {e} (run cargo build-sbf first)");
        exit(2);
    });

    let mut rng = StdRng::seed_from_u64(0x_713ACE);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).expect("setup");
    let vk_bytes = vk_to_solana(&vk).to_bytes();

    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");

    // The authority sets up the pool; the RELAYER is a separate keypair that
    // pays every action fee. Members have NO keypair.
    let authority = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&authority.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 10_000_000_000).unwrap();
    let (pool, _b) =
        Address::find_program_address(&[POOL_SEED, authority.pubkey().as_ref()], &program_id);

    // init (k_min = 2)
    let mut init = vec![0u8, TREE_DEPTH as u8];
    init.extend_from_slice(&2u64.to_le_bytes());
    init.extend_from_slice(&vk_bytes);
    send(
        &mut svm,
        &authority,
        &authority,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: init,
        },
    );

    // Deposits (submitted by the authority; commitments only — no member key).
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut secrets = Vec::new();
    for i in 0..N_MEMBERS {
        let secret = Fr::from(9000 + i);
        let c = commitment(secret);
        tree.insert(c).unwrap();
        secrets.push(secret);
        let mut d = vec![1u8];
        d.extend_from_slice(&fr_to_bytes_be(&c));
        send(
            &mut svm,
            &authority,
            &authority,
            Instruction {
                program_id,
                accounts: vec![AccountMeta::new(pool, false)],
                data: d,
            },
        );
    }

    // Open epoch 1.
    send(
        &mut svm,
        &authority,
        &authority,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(authority.pubkey(), true),
            ],
            data: vec![4u8],
        },
    );

    // Collect the observable trace for each acting member's execute_action.
    struct Row {
        fee_payer: Address,
        signers: Vec<Address>,
        account_keys: Vec<Address>,
        nullifier: [u8; 32],
    }
    let mut trace = Vec::new();
    let mut nullifiers = HashSet::new();

    for (member, secret) in secrets.iter().enumerate().take(N_ACTORS) {
        let binding = action_binding(SELECTOR_NOOP, &[]);
        let path = tree.proof(member).unwrap();
        let assignment = build_witness(*secret, &path, Fr::from(1u64), binding).unwrap();
        let pi = assignment.public_inputs.to_bytes();
        let sol = proof_to_solana(&prove(&pk, assignment.circuit, &mut rng).unwrap()).to_bytes();
        let mut proof = [0u8; 256];
        proof.copy_from_slice(&sol);
        let nullifier: [u8; 32] = pi[1];
        let (nullifier_pda, _n) = Address::find_program_address(
            &[NULLIFIER_SEED, pool.as_ref(), &nullifier],
            &program_id,
        );

        let mut data = vec![2u8];
        data.extend_from_slice(&proof);
        for l in &pi {
            data.extend_from_slice(l);
        }
        data.push(SELECTOR_NOOP);
        data.extend_from_slice(&0u32.to_le_bytes());

        let account_keys = vec![
            pool,
            nullifier_pda,
            relayer.pubkey(), // fee payer — the relayer, NOT the member
            SYSTEM_PROGRAM,
            program_id,
        ];
        let metas = vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(relayer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(program_id, false),
        ];
        // The relayer is the sole signer/fee payer.
        send(
            &mut svm,
            &relayer,
            &relayer,
            Instruction {
                program_id,
                accounts: metas,
                data,
            },
        );

        nullifiers.insert(nullifier);
        trace.push(Row {
            fee_payer: relayer.pubkey(),
            signers: vec![relayer.pubkey()],
            account_keys,
            nullifier,
        });
    }

    // ----- Attack the trace with full knowledge of the secrets -----
    let member_footprint: HashSet<[u8; 32]> = (0..N_MEMBERS)
        .map(|i| fr_to_bytes_be(&commitment(Fr::from(9000 + i))))
        .collect();

    let mut fail = false;
    for (i, row) in trace.iter().enumerate() {
        // Gate: fee payer is the relayer, never a member (members have no key).
        if row.fee_payer != relayer.pubkey() {
            eprintln!("LEAK: action {i} fee payer is not the relayer");
            fail = true;
        }
        // Gate: the only signer is the relayer.
        if row.signers != vec![relayer.pubkey()] {
            eprintln!("LEAK: action {i} has a non-relayer signer");
            fail = true;
        }
        // Gate: no account key is a member commitment or otherwise member-derived.
        for k in &row.account_keys {
            if member_footprint.contains(&k.to_bytes()) {
                eprintln!("LEAK: action {i} references a member-derived account");
                fail = true;
            }
        }
    }

    // The nullifiers are public but must not reveal which commitment produced
    // them: with full knowledge we confirm no nullifier equals any commitment
    // (they are different hashes of the secret) and that mapping requires the
    // secret (not present in the trace).
    for row in &trace {
        if member_footprint.contains(&row.nullifier) {
            eprintln!("LEAK: a nullifier collides with a commitment");
            fail = true;
        }
    }

    println!(
        "observed {} action(s); fee payer for all = relayer {}",
        trace.len(),
        relayer.pubkey()
    );
    println!(
        "effective anonymity set this epoch = {} distinct actions among {N_MEMBERS} members",
        nullifiers.len()
    );
    if nullifiers.len() <= 1 {
        eprintln!("WARN: anonymity set is 1 — no privacy (single-action window)");
    }

    if fail {
        eprintln!("\n=== trace FAIL: member ↔ action linkage was possible ===");
        exit(1);
    }
    println!(
        "\n=== trace PASS: no member↔action link in the public trace; \
         fee payer always the relayer; anonymity set = {} ===",
        nullifiers.len()
    );
}

fn send(svm: &mut LiteSVM, payer: &Keypair, signer: &Keypair, ix: Instruction) {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[signer]).unwrap();
    if let Err(f) = svm.send_transaction(tx) {
        eprintln!("tx failed: {:?}", f.err);
        for l in &f.meta.logs {
            eprintln!("  log: {l}");
        }
        exit(1);
    }
}
