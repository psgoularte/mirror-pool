//! Typed, on-chain program errors.
//!
//! Each variant maps to a stable `u32` so clients can match on failures
//! precisely (SPEC §7). Variants are appended (never reordered) as milestones
//! land their handlers, so the discriminants stay stable.

use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MirrorPoolError {
    #[error("instruction data could not be deserialized")]
    InvalidInstructionData = 0,

    #[error("the verifying key could not be parsed")]
    InvalidVerifyingKey = 1,

    #[error("the proof could not be parsed")]
    InvalidProof = 2,

    #[error("the membership proof failed verification")]
    ProofVerificationFailed = 3,

    #[error("an expected account was not provided")]
    MissingAccount = 4,

    #[error("the poseidon syscall failed")]
    PoseidonFailed = 5,

    #[error("the pool is already initialized")]
    AlreadyInitialized = 6,

    #[error("the pool account is not initialized")]
    NotInitialized = 7,

    #[error("unsupported tree depth")]
    InvalidTreeDepth = 8,

    #[error("the merkle tree is full")]
    TreeFull = 9,

    #[error("a required signature is missing")]
    MissingSignature = 10,

    #[error("the provided account address does not match the expected PDA")]
    InvalidPoolAddress = 11,

    #[error("the account is not owned by this program")]
    InvalidAccountOwner = 12,

    #[error("the proof's merkle root is not a known recent root")]
    UnknownRoot = 13,

    #[error("the proof's epoch does not match the pool's current epoch")]
    EpochMismatch = 14,

    #[error("the action binding does not match the requested action")]
    ActionBindingMismatch = 15,

    #[error("this nullifier has already been used in this epoch")]
    NullifierAlreadyUsed = 16,

    #[error("the nullifier account does not match the expected PDA")]
    InvalidNullifierAddress = 17,

    #[error("unknown action selector")]
    UnknownAction = 18,

    #[error("the pool PDA did not authorize this action")]
    UnauthorizedActor = 19,

    #[error("the pool has insufficient funds for this action")]
    InsufficientPoolFunds = 20,

    #[error("no epoch is currently open for actions")]
    EpochNotActive = 21,

    #[error("the epoch is already open")]
    EpochAlreadyOpen = 22,

    #[error("the signer is not the pool authority")]
    NotPoolAuthority = 23,

    #[error("deposit screening is enabled: a valid screening-authority signature is required")]
    ScreeningRequired = 24,
}

impl From<MirrorPoolError> for ProgramError {
    fn from(e: MirrorPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
