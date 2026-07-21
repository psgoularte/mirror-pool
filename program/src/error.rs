//! Typed, on-chain program errors.
//!
//! Each variant maps to a stable `u32` so clients can match on failures
//! precisely (SPEC §7). Variants are added as milestones land their handlers.

use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MirrorPoolError {
    #[error("instruction data could not be deserialized")]
    InvalidInstructionData = 0,
}

impl From<MirrorPoolError> for ProgramError {
    fn from(e: MirrorPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
