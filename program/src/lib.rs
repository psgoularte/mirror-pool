//! `mirror-pool` on-chain program (native `solana-program`, no Anchor).
//!
//! Milestones fill in the modules over time:
//!
//! * M3 (here) — Groth16 membership-proof verification via `groth16-solana`,
//!   exposed as the `VerifyMembership` instruction and benchmarked for compute
//!   units. Nothing builds on top until this verifies a real arkworks proof
//!   under budget.
//! * M4 — incremental Merkle tree + `deposit` with a root-history buffer.
//! * M5 — nullifier set + `execute_action` gated by the membership proof.
//! * M6 — epochs + one real protocol integration via PDA-signed CPI.
//! * M7 — compliance: viewing keys / selective disclosure + screening hook.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

pub mod error;
pub mod instruction;
pub mod verifier;

use instruction::Instruction;
use verifier::ParsedVerifyingKey;

#[cfg(all(not(feature = "no-entrypoint"), target_os = "solana"))]
solana_program::entrypoint!(process_instruction);

/// Instruction dispatcher. Never panics — failures return typed
/// [`error::MirrorPoolError`] values (SPEC §7).
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match Instruction::unpack(instruction_data)? {
        Instruction::VerifyMembership {
            proof,
            public_inputs,
        } => process_verify_membership(accounts, &proof, &public_inputs),
    }
}

/// `VerifyMembership`: read the verifying key from the first account, then
/// verify the supplied proof/public-inputs through `groth16-solana`.
///
/// In later milestones this verification moves inside `execute_action` and the
/// VK lives in the pool-config PDA; here the VK account is passed directly so
/// the compute cost of verification can be measured in isolation.
fn process_verify_membership(
    accounts: &[AccountInfo],
    proof: &[u8; verifier::PROOF_LEN],
    public_inputs: &[[u8; 32]; verifier::NUM_PUBLIC_INPUTS],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vk_account = next_account_info(account_iter)?;

    let vk_data = vk_account.try_borrow_data()?;
    let vk = ParsedVerifyingKey::parse(&vk_data)?;

    verifier::verify_membership(&vk, proof, public_inputs)?;
    msg!("mirror-pool: membership proof verified");
    Ok(())
}
