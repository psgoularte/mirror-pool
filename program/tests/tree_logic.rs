//! Host tests for the on-chain Merkle tree logic (milestone 4).
//!
//! These validate the incremental tree against the off-chain reference and,
//! crucially, that the on-chain Poseidon path (`solana-poseidon`, i.e. the
//! `sol_poseidon` syscall on BPF) is byte-identical to `common::poseidon` — the
//! hasher the circuit gadget mirrors. That closes the circuit↔chain hashing
//! loop with the actual on-chain hasher.

use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use bytemuck::Zeroable;
use mirror_pool_circuit::Fr;
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::{fr_to_bytes_be, poseidon, ROOT_HISTORY_SIZE, TREE_DEPTH};
use mirror_pool_program::merkle::hash_pair;
use mirror_pool_program::state::PoolConfig;

const AUTHORITY: [u8; 32] = [7u8; 32];

fn new_pool() -> PoolConfig {
    let mut cfg = PoolConfig::zeroed();
    // Tree-logic tests never verify proofs, so a zero verifying key is fine.
    let vk = [0u8; mirror_pool_program::verifier::VK_SERIALIZED_LEN];
    cfg.initialize(AUTHORITY, 254, TREE_DEPTH as u8, &vk)
        .unwrap();
    cfg
}

#[test]
fn pool_config_len_matches_size() {
    assert_eq!(std::mem::size_of::<PoolConfig>(), PoolConfig::LEN);
    let cfg = new_pool();
    assert_eq!(bytemuck::bytes_of(&cfg).len(), PoolConfig::LEN);
}

#[test]
fn onchain_poseidon_matches_common() {
    // The on-chain two-to-one hash must equal common::poseidon::hash_pair for
    // the same field elements. common is proven equal to light-poseidon (the
    // syscall implementation), so this ties the program to the circuit.
    let mut rng = StdRng::seed_from_u64(9);
    for _ in 0..64 {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let onchain = hash_pair(&fr_to_bytes_be(&a), &fr_to_bytes_be(&b)).unwrap();
        let native = fr_to_bytes_be(&poseidon::hash_pair(a, b));
        assert_eq!(onchain, native);
    }
}

#[test]
fn incremental_root_matches_reference() {
    // Insert the same commitments into the on-chain incremental tree and the
    // off-chain reference tree; the roots must match at every step.
    let mut cfg = new_pool();
    let mut reference = MerkleTree::new(TREE_DEPTH);

    // Empty-tree roots agree.
    assert_eq!(cfg.current_root, fr_to_bytes_be(&reference.root()));

    for i in 0..40u64 {
        let commitment = poseidon::commitment(Fr::from(i + 1));
        let idx = cfg.insert(fr_to_bytes_be(&commitment)).unwrap();
        reference.insert(commitment).unwrap();
        assert_eq!(idx, i);
        assert_eq!(
            cfg.current_root,
            fr_to_bytes_be(&reference.root()),
            "root mismatch after {} inserts",
            i + 1
        );
    }
}

#[test]
fn known_root_tracks_history() {
    let mut cfg = new_pool();
    let mut roots = Vec::new();
    for i in 0..5u64 {
        cfg.insert(fr_to_bytes_be(&poseidon::commitment(Fr::from(i + 1))))
            .unwrap();
        roots.push(cfg.current_root);
    }
    // Every recent root is recognized; a fabricated root is not.
    for r in &roots {
        assert!(cfg.is_known_root(r));
    }
    assert!(!cfg.is_known_root(&[9u8; 32]));
    assert!(!cfg.is_known_root(&[0u8; 32]), "all-zero is never a root");
}

#[test]
fn old_root_evicted_after_history_fills() {
    let mut cfg = new_pool();
    cfg.insert(fr_to_bytes_be(&poseidon::commitment(Fr::from(1u64))))
        .unwrap();
    let first_root = cfg.current_root;
    assert!(cfg.is_known_root(&first_root));
    // Fill the ring buffer past capacity; the first root should be evicted.
    for i in 0..(ROOT_HISTORY_SIZE as u64 + 2) {
        cfg.insert(fr_to_bytes_be(&poseidon::commitment(Fr::from(i + 100))))
            .unwrap();
    }
    assert!(
        !cfg.is_known_root(&first_root),
        "root should age out of the ring buffer"
    );
}

#[test]
fn tree_full_is_rejected() {
    let mut cfg = new_pool();
    // Jump to capacity without doing 1M real inserts.
    cfg.next_index = (1u64 << TREE_DEPTH).to_le_bytes();
    let err = cfg
        .insert(fr_to_bytes_be(&poseidon::commitment(Fr::from(1u64))))
        .unwrap_err();
    assert_eq!(
        err,
        mirror_pool_program::error::MirrorPoolError::TreeFull.into()
    );
}
