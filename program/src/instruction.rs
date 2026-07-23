//! Instruction encoding for the mirror-pool program (borsh).
//!
//! Discriminants are assigned by declaration order. The production instructions
//! occupy the stable range 0..=7. `VerifyMembership` is a **benchmark-only**
//! instruction gated behind the `bench` feature; it is declared LAST so that
//! enabling/disabling the feature never shifts a production discriminant, and it
//! is entirely absent from the default (deployed) build (SECURITY: it read an
//! unchecked verifying-key account and is pure benchmark surface).

use crate::error::MirrorPoolError;
use crate::verifier::{NUM_PUBLIC_INPUTS, PROOF_LEN, VK_SERIALIZED_LEN};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_error::ProgramError;

#[allow(clippy::large_enum_variant)]
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// (0) Create and initialize a pool config PDA with an empty tree of
    /// `depth`, a minimum anonymity set `k_min`, the membership circuit's
    /// verifying key, and an anti-Sybil `entry_fee` in lamports (`0` disables
    /// it, preserving permissionless deposits). `entry_fee` is the **last**
    /// field so the encoding stays append-only.
    InitializePool {
        depth: u8,
        k_min: u64,
        verifying_key: [u8; VK_SERIALIZED_LEN],
        entry_fee: u64,
    },

    /// (1) Insert a commitment leaf into the pool's Merkle tree.
    Deposit { commitment: [u8; 32] },

    /// (2) Verify a membership proof and, if valid and unused this epoch, execute
    /// the selected action via a PDA-signed CPI. Marks the nullifier.
    ExecuteAction {
        proof: [u8; PROOF_LEN],
        public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
        action_selector: u8,
        action_params: Vec<u8>,
    },

    /// (3) Internal: the no-op action's CPI target. Only valid when invoked by
    /// the pool PDA (as a signer). Not meant to be called directly.
    NoOpAction,

    /// (4) Crank: open a new epoch window (authority only). Actions are valid
    /// only while an epoch is open.
    OpenEpoch,

    /// (5) Crank: close the current epoch window (authority only).
    CloseEpoch,

    /// (6) Set (or clear, with all-zero) the deposit-screening authority
    /// (authority only). When set, deposits must be co-signed by it.
    SetScreeningAuthority { authority: [u8; 32] },

    /// (7) Register a selective-disclosure record: the member's commitment, the
    /// designated auditor, and the member's secret sealed to that auditor.
    RegisterViewingKey {
        commitment: [u8; 32],
        auditor: [u8; 32],
        sealed_secret: Vec<u8>,
    },

    /// (8, `bench` feature only) Verify a membership proof against a verifying
    /// key supplied in the first account, and log the result. Benchmark-only;
    /// NOT compiled into the deployed program.
    #[cfg(feature = "bench")]
    VerifyMembership {
        proof: [u8; PROOF_LEN],
        public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
    },
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
