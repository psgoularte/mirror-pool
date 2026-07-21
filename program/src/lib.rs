//! `mirror-pool` on-chain program (native `solana-program`, no Anchor).
//!
//! Milestone 1 ships the crate skeleton and a minimal entrypoint so the
//! `build-sbf` toolchain path is exercised in CI from day one. Subsequent
//! milestones fill in the modules below:
//!
//! * M4 — incremental Merkle tree + `deposit` with a root-history buffer.
//! * M5 — nullifier set + `execute_action` gated by a Groth16 membership proof.
//! * M6 — epochs + one real protocol integration via PDA-signed CPI.
//! * M7 — compliance: viewing keys / selective disclosure + screening hook.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

pub mod error;

// The BPF entrypoint is compiled only for the on-chain target and can be
// disabled by dependents that link this crate purely for its types.
#[cfg(all(not(feature = "no-entrypoint"), target_os = "solana"))]
solana_program::entrypoint!(process_instruction);

/// Instruction dispatcher.
///
/// Milestone 1 has no instructions yet; the handler exists so the program
/// links, deploys, and returns cleanly. It never panics — the SPEC forbids
/// `unwrap`/`expect`/`panic` in handlers.
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}
