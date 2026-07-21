//! Typed errors shared across mirror-pool crates.
//!
//! Every failure path in the protocol maps to one of these variants — there
//! are no silent fallbacks and no stringly-typed errors (SPEC §7, "fail loud").

use thiserror::Error;

/// Errors produced by the shared cryptographic primitives in `common`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommonError {
    /// A byte slice handed to a field deserializer was not exactly 32 bytes.
    #[error("invalid field-element encoding: expected 32 bytes, got {0}")]
    InvalidFieldLength(usize),

    /// A 32-byte value was >= the BN254 scalar field modulus and therefore is
    /// not a canonical field element. We reject rather than silently reduce it,
    /// because reduction would let two distinct encodings collide.
    #[error("field element is not canonical (>= BN254 scalar modulus)")]
    NonCanonicalField,

    /// The requested Poseidon arity is unsupported by the pinned parameter set.
    #[error("unsupported Poseidon arity {0} (supported: 1, 2)")]
    UnsupportedArity(usize),

    /// The underlying Poseidon implementation rejected the inputs. Carries the
    /// upstream message so drift in `light-poseidon` surfaces loudly.
    #[error("poseidon hashing failed: {0}")]
    Poseidon(String),

    /// A Merkle authentication path did not have the expected depth.
    #[error("merkle path length {got} does not match tree depth {expected}")]
    MerklePathLength { got: usize, expected: usize },
}

pub type Result<T> = core::result::Result<T, CommonError>;
