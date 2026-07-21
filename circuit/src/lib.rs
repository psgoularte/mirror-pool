//! `mirror-pool-circuit` — arkworks Groth16/BN254 membership circuit + prover.
//!
//! Milestone 1 ships the crate skeleton; milestone 2 lands the circuit:
//!
//! * private inputs: `secret`, Merkle `path_elements[]`, `path_indices[]`;
//! * public inputs: `merkle_root`, `nullifier_hash`, `epoch_id`,
//!   `action_binding`;
//! * constraints: commitment + Merkle inclusion, epoch-scoped nullifier,
//!   action binding.
//!
//! The Poseidon gadget in this crate reproduces the permutation from
//! [`mirror_pool_common::poseidon`] constraint-for-constraint, so a witness
//! valid in-circuit hashes identically to the native prover and the on-chain
//! `sol_poseidon` syscall.

// Re-exported so downstream crates get the field type from one place.
pub use ark_bn254::Fr;
pub use mirror_pool_common as common;
