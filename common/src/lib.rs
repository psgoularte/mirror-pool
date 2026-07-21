//! `mirror-pool-common` — shared types and the single source of truth for the
//! protocol's cryptographic constants.
//!
//! Nothing in here depends on Solana or arkworks' R1CS machinery, so it is
//! cheap to import from every other crate (circuit, program, relayer, CLI)
//! without pulling in heavy or target-specific dependencies. The one job of
//! this crate is to make sure everyone hashes, encodes, and sizes things the
//! same way.

pub mod error;
pub mod field;
pub mod poseidon;

pub use error::{CommonError, Result};
pub use field::{fr_from_bytes_be, fr_to_bytes_be, Bytes32, FIELD_BYTES};

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
