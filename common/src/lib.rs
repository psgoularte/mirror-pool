//! `mirror-pool-common` — shared types and the single source of truth for the
//! protocol's cryptographic constants.
//!
//! The pure protocol constants below (tree dimensions, field width) have no
//! external dependencies, so the on-chain program can import them cheaply. The
//! cryptographic modules ([`field`], [`poseidon`], [`merkle`]) pull arkworks and
//! `light-poseidon` and are gated behind the default `crypto` feature; the
//! program depends on this crate with `default-features = false` and hashes via
//! the `sol_poseidon` syscall instead.
#![deny(missing_docs)]

pub mod error;

#[cfg(feature = "crypto")]
pub mod compliance;
#[cfg(feature = "crypto")]
pub mod field;
#[cfg(feature = "crypto")]
pub mod merkle;
#[cfg(feature = "crypto")]
pub mod poseidon;

pub use error::{CommonError, Result};

#[cfg(feature = "crypto")]
pub use ark_bn254::Fr;
#[cfg(feature = "crypto")]
pub use field::{fr_from_bytes_be, fr_to_bytes_be};

/// Byte length of a serialized field element / hash digest.
pub const FIELD_BYTES: usize = 32;

/// A canonical 32-byte big-endian field element (leaf, root, nullifier, …).
pub type Bytes32 = [u8; FIELD_BYTES];

/// Depth of the incremental Merkle tree (number of levels below the root).
///
/// A depth-20 tree holds up to `2^20 ≈ 1.05M` commitments — large enough for a
/// meaningful anonymity set while keeping the in-circuit path short (20 hashes)
/// and the on-chain filled-subtree array small.
pub const TREE_DEPTH: usize = 20;

/// Maximum number of commitments the tree can hold.
pub const MAX_LEAVES: u64 = 1 << TREE_DEPTH;

/// Number of recent roots the on-chain program retains in its ring buffer.
///
/// A proof is generated against whatever root was current when the prover read
/// the tree; by the time the transaction lands, other deposits may have
/// advanced the root. Retaining the last `ROOT_HISTORY_SIZE` roots lets a proof
/// against any recent root stay valid (SPEC §7, "keep the root-history
/// buffer"). Without it, proofs race tree updates and fail unpredictably.
pub const ROOT_HISTORY_SIZE: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_constants_are_consistent() {
        assert_eq!(MAX_LEAVES, 1u64 << TREE_DEPTH);
        assert!(ROOT_HISTORY_SIZE.is_power_of_two());
    }
}
