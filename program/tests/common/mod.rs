//! Shared fixture: a real membership proof + verifying key, produced by the
//! circuit crate. Used by both the host correctness test and the fixture
//! generator so they exercise identical, genuine cryptography.
//!
//! Compiled independently into each test binary, so not every field is read in
//! every consumer.
#![allow(dead_code)]

use mirror_pool_circuit::prover::{build_witness, prove, setup};
use mirror_pool_circuit::solana::{proof_to_solana, vk_to_solana};
use mirror_pool_circuit::Fr;
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon;
use mirror_pool_common::TREE_DEPTH;
#[cfg(feature = "bench")]
use mirror_pool_program::instruction::Instruction;
use mirror_pool_program::verifier::{NUM_PUBLIC_INPUTS, PROOF_LEN};

use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;

pub struct Fixture {
    /// Verifying key in the program's flat byte layout (account data).
    pub vk_bytes: Vec<u8>,
    pub proof: [u8; PROOF_LEN],
    pub public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
    /// Ready-to-send `VerifyMembership` instruction data (tag + payload).
    /// Only built with the `bench` feature (the instruction is benchmark-only).
    #[cfg(feature = "bench")]
    pub instruction_data: Vec<u8>,
}

/// Build a fixture proving membership of member #3 in an 8-leaf pool.
///
/// Deterministic (seeded) so the benchmark is reproducible.
pub fn membership_fixture() -> Fixture {
    let mut rng = StdRng::seed_from_u64(0x4D33_BE0C);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).expect("setup");

    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut member_secret = Fr::from(0u64);
    for i in 0..8u64 {
        let s = Fr::rand(&mut rng);
        if i == 3 {
            member_secret = s;
        }
        tree.insert(poseidon::commitment(s)).expect("insert");
    }
    let path = tree.proof(3).expect("path");

    let assignment = build_witness(member_secret, &path, Fr::from(123u64), Fr::from(0xF00Du64))
        .expect("witness");
    let public = assignment.public_inputs.clone();
    let proof = prove(&pk, assignment.circuit, &mut rng).expect("prove");

    let sol_vk = vk_to_solana(&vk);
    let sol_proof = proof_to_solana(&proof);
    let pi_bytes = public.to_bytes();
    let public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS] =
        [pi_bytes[0], pi_bytes[1], pi_bytes[2], pi_bytes[3]];
    let proof_flat = sol_proof.to_bytes();

    #[cfg(feature = "bench")]
    let instruction_data = Instruction::VerifyMembership {
        proof: proof_flat,
        public_inputs,
    }
    .pack()
    .expect("pack verify instruction");

    Fixture {
        vk_bytes: sol_vk.to_bytes(),
        proof: proof_flat,
        public_inputs,
        #[cfg(feature = "bench")]
        instruction_data,
    }
}
