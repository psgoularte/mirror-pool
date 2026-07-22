//! Instruction encoding for the mirror-pool program (borsh).
//!
//! Milestone 3 added `VerifyMembership`; milestone 4 adds `InitializePool` and
//! `Deposit`. Variant order is stable (append-only) so the borsh discriminant
//! for each instruction never changes — the CU-benchmark fixture depends on
//! `VerifyMembership` staying variant 0.

use crate::error::MirrorPoolError;
use crate::verifier::{NUM_PUBLIC_INPUTS, PROOF_LEN, VK_SERIALIZED_LEN};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_error::ProgramError;

// `VerifyMembership` carries a 384-byte fixed payload; the other variants are
// small. Boxing it would only move a fixed-size blob to the heap and complicate
// the on-chain (no-alloc-friendly) decode, so the size skew is intentional.
#[allow(clippy::large_enum_variant)]
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Verify a membership proof against the verifying key in the first
    /// account. Carries the proof (`a||b||c`, `a` negated) and the public
    /// inputs (big-endian). Variant 0 — do not move.
    VerifyMembership {
        proof: [u8; PROOF_LEN],
        public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
    },

    /// Create and initialize a pool config PDA with an empty tree of `depth`
    /// and the membership circuit's verifying key.
    InitializePool {
        depth: u8,
        verifying_key: [u8; VK_SERIALIZED_LEN],
    },

    /// Insert a commitment leaf into the pool's Merkle tree.
    Deposit { commitment: [u8; 32] },

    /// Verify a membership proof and, if valid and unused this epoch, execute
    /// the selected action via a PDA-signed CPI. Marks the nullifier.
    ExecuteAction {
        proof: [u8; PROOF_LEN],
        public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
        action_selector: u8,
        action_params: Vec<u8>,
    },

    /// Internal: the no-op action's CPI target. Only valid when invoked by the
    /// pool PDA (as a signer). Not meant to be called directly.
    NoOpAction,

    /// Crank: open a new epoch window (authority only). Actions are valid only
    /// while an epoch is open.
    OpenEpoch,

    /// Crank: close the current epoch window (authority only).
    CloseEpoch,
}

impl Instruction {
    /// Decode instruction data, rejecting trailing bytes.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        Self::try_from_slice(data)
            .map_err(|_| ProgramError::from(MirrorPoolError::InvalidInstructionData))
    }

    /// Encode to instruction data.
    pub fn pack(&self) -> Result<Vec<u8>, ProgramError> {
        borsh::to_vec(self).map_err(|_| ProgramError::from(MirrorPoolError::InvalidInstructionData))
    }
}
