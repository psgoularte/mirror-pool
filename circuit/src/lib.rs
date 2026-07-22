//! `mirror-pool-circuit` — arkworks Groth16/BN254 membership circuit + prover.
//!
//! Proves pool membership and the right to act in an epoch without revealing
//! which member. See [`circuit::MembershipCircuit`] for the statement and
//! [`prover`] for setup/prove/verify and the canonical public-input encoding.
//!
//! The Poseidon gadget ([`poseidon_gadget`]) reproduces the permutation from
//! [`mirror_pool_common::poseidon`] constraint-for-constraint, so a witness
//! valid in-circuit hashes identically to the native prover and the on-chain
//! `sol_poseidon` syscall.

#![deny(missing_docs)]

pub mod association;
pub mod ceremony;
pub mod circuit;
pub mod error;
pub mod poseidon_gadget;
pub mod prover;
pub mod solana;

// Re-exported so downstream crates get the field type from one place.
pub use ark_bn254::Fr;
pub use circuit::MembershipCircuit;
pub use error::{CircuitError, Result};
pub use mirror_pool_common as common;
pub use prover::{build_witness, setup, Assignment, PublicInputs};
