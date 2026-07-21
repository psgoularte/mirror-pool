//! On-chain incremental Merkle tree primitives.
//!
//! Hashing goes through the `sol_poseidon` syscall (circom BN254 `x5`,
//! big-endian), so a root computed here is byte-identical to one the circuit
//! proved membership under and to `mirror_pool_common::merkle` off-chain. The
//! incremental "filled subtrees" construction lets a `deposit` update the root
//! in `TREE_DEPTH` hashes without storing the whole tree.

use crate::error::MirrorPoolError;
use solana_poseidon::{hashv, Endianness, Parameters};
use solana_program::program_error::ProgramError;

/// Two-to-one node hash via the on-chain Poseidon syscall.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let h = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[left, right])
        .map_err(|_| ProgramError::from(MirrorPoolError::PoseidonFailed))?;
    Ok(h.to_bytes())
}

/// Compute the empty-subtree ("zero") hashes for a tree of `depth`.
///
/// `zeros[0]` is the empty leaf; `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`.
/// Returns `depth + 1` values (the last is the empty-tree root). Used once at
/// pool initialization.
pub fn zero_hashes(depth: usize) -> Result<Vec<[u8; 32]>, ProgramError> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push([0u8; 32]);
    for i in 1..=depth {
        let prev = zeros[i - 1];
        zeros.push(hash_pair(&prev, &prev)?);
    }
    Ok(zeros)
}
