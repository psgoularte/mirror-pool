//! Full-flow end-to-end test against the actual SBF bytecode (milestones 5–6):
//! initialize → deposit → open epoch → prove → `execute_action` for both the
//! no-op (PDA-signed CPI) and the real SOL-transfer action, then exercise the
//! security negatives (replay, action-binding mismatch, tampered proof, wrong
//! epoch, epoch-not-active).
//!
//! Genuine cryptography throughout. Run (after `cargo build-sbf`):
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
use solana_compute_budget_interface::ComputeBudgetInstruction;
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
const SELECTOR_TRANSFER: u8 = 1;

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

    let mut rng = StdRng::seed_from_u64(0x5EED_0006);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).expect("setup");
    let vk_bytes = vk_to_solana(&vk).to_bytes();

    let mut svm = LiteSVM::new();
    let program_id = Address::new_unique();
    svm.add_program(program_id, &elf).expect("add program");
    let payer = Keypair::new(); // deployer + pool authority + relayer
    svm.airdrop(&payer.pubkey(), 20_000_000_000)
        .expect("airdrop");
    let (pool, _bump) =
        Address::find_program_address(&[POOL_SEED, payer.pubkey().as_ref()], &program_id);

    // 1) InitializePool { depth, verifying_key } (borsh variant 1).
    let mut init_data = vec![1u8, TREE_DEPTH as u8];
    init_data.extend_from_slice(&vk_bytes);
    send(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: init_data,
        },
        "initialize_pool",
    );
    // Give the pool PDA surplus lamports so the transfer action has funds.
    svm.airdrop(&pool, 3_000_000_000).expect("fund pool");

    // 2) Deposit member commitments (mirror off-chain to build witnesses).
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut secrets = Vec::new();
    for i in 0..4u64 {
        let secret = Fr::from(2000 + i);
        let c = commitment(secret);
        tree.insert(c).unwrap();
        secrets.push(secret);
        let mut data = vec![2u8];
        data.extend_from_slice(&fr_to_bytes_be(&c));
        send(
            &mut svm,
            &payer,
            Instruction {
                program_id,
                accounts: vec![AccountMeta::new(pool, false)],
                data,
            },
            &format!("deposit[{i}]"),
        );
    }

    // 3) OpenEpoch (crank; variant 5) → epoch becomes 1 and active.
    send(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            data: vec![5u8],
        },
        "open_epoch",
    );
    let epoch: u64 = 1;

    let mut prove_member = |member: usize, epoch: u64, selector: u8, params: &[u8]| {
        let binding = action_binding(selector, params);
        let path = tree.proof(member).unwrap();
        let assignment = build_witness(secrets[member], &path, Fr::from(epoch), binding).unwrap();
        let pi = assignment.public_inputs.to_bytes();
        let sol = proof_to_solana(&prove(&pk, assignment.circuit, &mut rng).unwrap()).to_bytes();
        let mut proof = [0u8; 256];
        proof.copy_from_slice(&sol);
        let mut limbs = [[0u8; 32]; 4];
        for (i, l) in pi.iter().enumerate() {
            limbs[i] = *l;
        }
        (proof, limbs)
    };

    // 4) No-op action (member 2): self-CPI proving the pool PDA signs. The
    //    transaction explicitly requests a CU budget (VALIDATION L4) and we
    //    assert the measured cost stays comfortably under it.
    let (proof, pi) = prove_member(2, epoch, SELECTOR_NOOP, &[]);
    let noop_ix = exec_ix(
        program_id,
        pool,
        &proof,
        &pi,
        SELECTOR_NOOP,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)], // CPI target: self
    );
    const CU_LIMIT: u32 = 300_000;
    let cu = send_cu(
        &mut svm,
        &payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT),
            noop_ix,
        ],
        "execute_action(no-op)",
    );
    if cu >= 200_000 {
        eprintln!("FAIL: execute_action consumed {cu} CU, over the 200k soft budget");
        exit(1);
    }
    println!("[cu] execute_action = {cu} CU (< 200k soft budget, requested {CU_LIMIT})");

    // Stale/unknown Merkle root: a valid proof carrying a fabricated root is
    // refused before verification (root check precedes it). VALIDATION L2.
    let mut stale_pi = pi;
    stale_pi[0] = [0xAB; 32]; // a root never in the history buffer
    let stale = exec_ix(
        program_id,
        pool,
        &proof,
        &stale_pi,
        SELECTOR_NOOP,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject(&mut svm, &payer, stale, "stale/unknown root", 13);

    // 5) Real transfer action (member 0): pool disburses SOL to a recipient,
    //    with the amount+recipient bound into the proof.
    let recipient = Address::new_unique();
    let amount: u64 = 750_000_000;
    let mut params = amount.to_le_bytes().to_vec();
    params.extend_from_slice(recipient.as_ref());
    let (proof_t, pi_t) = prove_member(0, epoch, SELECTOR_TRANSFER, &params);
    let transfer_ix = exec_ix(
        program_id,
        pool,
        &proof_t,
        &pi_t,
        SELECTOR_TRANSFER,
        &params,
        payer.pubkey(),
        vec![AccountMeta::new(recipient, false)], // ctx.accounts[0] = recipient
    );
    send(&mut svm, &payer, transfer_ix, "execute_action(transfer)");
    let bal = svm.get_account(&recipient).map(|a| a.lamports).unwrap_or(0);
    if bal != amount {
        eprintln!("FAIL: recipient balance {bal} != {amount}");
        exit(1);
    }
    println!("[transfer] recipient received {bal} lamports from the pool PDA");

    // 6) Negatives.
    // Replay the no-op with a different fee payer (distinct tx) → nullifier used.
    let relayer2 = Keypair::new();
    svm.airdrop(&relayer2.pubkey(), 1_000_000_000).unwrap();
    let replay = exec_ix(
        program_id,
        pool,
        &proof,
        &pi,
        SELECTOR_NOOP,
        &[],
        relayer2.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject(&mut svm, &relayer2, replay, "replay (spent nullifier)", 16);

    // Action-binding mismatch: no-op proof but claim the transfer selector.
    let mismatch = exec_ix(
        program_id,
        pool,
        &proof,
        &pi,
        SELECTOR_TRANSFER,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject(&mut svm, &payer, mismatch, "action-binding mismatch", 15);

    // Tampered proof (fresh member 3).
    let (mut bad, pi3) = prove_member(3, epoch, SELECTOR_NOOP, &[]);
    bad[0] ^= 0x01;
    let tampered = exec_ix(
        program_id,
        pool,
        &bad,
        &pi3,
        SELECTOR_NOOP,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject_any(&mut svm, &payer, tampered, "tampered proof", &[2, 3]);

    // Wrong epoch: prove against epoch 2 while epoch 1 is open.
    let (proof_e2, pi_e2) = prove_member(1, 2, SELECTOR_NOOP, &[]);
    let wrong_epoch = exec_ix(
        program_id,
        pool,
        &proof_e2,
        &pi_e2,
        SELECTOR_NOOP,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject(&mut svm, &payer, wrong_epoch, "wrong epoch", 14);

    // Epoch not active: close the epoch, then a valid proof is refused.
    send(
        &mut svm,
        &payer,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            data: vec![6u8], // CloseEpoch
        },
        "close_epoch",
    );
    let (proof1, pi1) = prove_member(1, epoch, SELECTOR_NOOP, &[]);
    let closed = exec_ix(
        program_id,
        pool,
        &proof1,
        &pi1,
        SELECTOR_NOOP,
        &[],
        payer.pubkey(),
        vec![AccountMeta::new_readonly(program_id, false)],
    );
    expect_reject(&mut svm, &payer, closed, "epoch not active", 21);

    // Admin abuse (VALIDATION L5): re-initialization and an unauthorized crank.
    let mut reinit = vec![1u8, TREE_DEPTH as u8];
    reinit.extend_from_slice(&vk_bytes);
    // Prepend a compute-budget ix so this isn't byte-identical to the original
    // init tx (which would be deduped as already-processed before running).
    expect_reject_ixs(
        &mut svm,
        &payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(50_000),
            Instruction {
                program_id,
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(pool, false),
                    AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                ],
                data: reinit,
            },
        ],
        "re-initialization",
        &[6], // AlreadyInitialized
    );

    let stranger = Keypair::new();
    svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    expect_reject(
        &mut svm,
        &stranger,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(stranger.pubkey(), true),
            ],
            data: vec![5u8], // OpenEpoch by a non-authority
        },
        "unauthorized crank",
        23, // NotPoolAuthority
    );

    println!(
        "\n=== flow PASS: no-op + real transfer executed via pool PDA; \
         replay/binding/tampered/wrong-epoch/closed-epoch/re-init/unauthorized all rejected ==="
    );
}

/// Build an `ExecuteAction` instruction (borsh variant 3). `trailing` are the
/// action-specific accounts (index 4 onward): the CPI target for the no-op, or
/// the recipient for the transfer.
#[allow(clippy::too_many_arguments)]
fn exec_ix(
    program_id: Address,
    pool: Address,
    proof: &[u8; 256],
    pi: &[[u8; 32]; 4],
    selector: u8,
    params: &[u8],
    fee_payer: Address,
    trailing: Vec<AccountMeta>,
) -> Instruction {
    let (nullifier_pda, _b) = Address::find_program_address(&[NULLIFIER_SEED, &pi[1]], &program_id);
    let mut data = vec![3u8];
    data.extend_from_slice(proof);
    for limb in pi {
        data.extend_from_slice(limb);
    }
    data.push(selector);
    data.extend_from_slice(&(params.len() as u32).to_le_bytes());
    data.extend_from_slice(params);
    let mut accounts = vec![
        AccountMeta::new(pool, false), // writable (transfer moves pool lamports)
        AccountMeta::new(nullifier_pda, false),
        AccountMeta::new(fee_payer, true),
        AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
    ];
    accounts.extend(trailing);
    Instruction {
        program_id,
        accounts,
        data,
    }
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction, label: &str) {
    send_cu(svm, payer, &[ix], label);
}

/// Send one or more instructions; return the compute units consumed.
fn send_cu(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], label: &str) -> u64 {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
    match svm.send_transaction(tx) {
        Ok(meta) => {
            println!("[{label}] ok, {} CU", meta.compute_units_consumed);
            meta.compute_units_consumed
        }
        Err(failed) => {
            eprintln!("FAIL[{label}]: {:?}", failed.err);
            for l in &failed.meta.logs {
                eprintln!("  log: {l}");
            }
            exit(1);
        }
    }
}

fn expect_reject(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction, label: &str, code: u32) {
    expect_reject_ixs(svm, payer, &[ix], label, &[code]);
}

fn expect_reject_any(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ix: Instruction,
    label: &str,
    codes: &[u32],
) {
    expect_reject_ixs(svm, payer, &[ix], label, codes);
}

/// Reject-expecting send over a full instruction list (lets callers prepend a
/// compute-budget instruction to make an otherwise-identical tx distinct, so it
/// runs rather than being deduped as already-processed).
fn expect_reject_ixs(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
    label: &str,
    codes: &[u32],
) {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => {
            eprintln!("FAIL[{label}]: expected rejection, but the tx succeeded");
            exit(1);
        }
        Err(failed) => {
            let s = format!("{:?}", failed.err);
            if codes.iter().any(|c| s.contains(&format!("Custom({c})"))) {
                println!("[{label}] correctly rejected: {s}");
            } else {
                eprintln!("FAIL[{label}]: rejected but not with Custom{codes:?}: {s}");
                exit(1);
            }
        }
    }
}
