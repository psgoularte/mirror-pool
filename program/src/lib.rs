//! `mirror-pool` on-chain program (native `solana-program`, no Anchor).
//!
//! Milestones fill in the modules over time:
//!
//! * M3 — Groth16 membership-proof verification via `groth16-solana`
//!   (`VerifyMembership`), benchmarked under the compute budget.
//! * M4 (here) — incremental Merkle tree + `deposit` with a root-history buffer
//!   (`InitializePool`, `Deposit`).
//! * M5 — nullifier set + `execute_action` gated by the membership proof.
//! * M6 — epochs + one real protocol integration via PDA-signed CPI.
//! * M7 — compliance: viewing keys / selective disclosure + screening hook.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::Instruction as SolInstruction,
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

pub mod error;
pub mod instruction;
pub mod merkle;
pub mod state;
pub mod verifier;

use error::MirrorPoolError;
use instruction::Instruction;
use state::{PoolConfig, POOL_SEED};
use verifier::ParsedVerifyingKey;

#[cfg(all(not(feature = "no-entrypoint"), target_os = "solana"))]
solana_program::entrypoint!(process_instruction);

/// Instruction dispatcher. Never panics — failures return typed
/// [`error::MirrorPoolError`] values (SPEC §7).
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match Instruction::unpack(instruction_data)? {
        Instruction::VerifyMembership {
            proof,
            public_inputs,
        } => process_verify_membership(accounts, &proof, &public_inputs),
        Instruction::InitializePool { depth } => {
            process_initialize_pool(program_id, accounts, depth)
        }
        Instruction::Deposit { commitment } => process_deposit(program_id, accounts, commitment),
    }
}

/// `VerifyMembership`: read the verifying key from the first account, then
/// verify the supplied proof/public-inputs through `groth16-solana`.
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

/// `InitializePool`: create the pool-config PDA (seeds `["pool", authority]`)
/// and write an empty-tree [`PoolConfig`]. The payer becomes the pool authority.
fn process_initialize_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    depth: u8,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;
    let pool_account = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }

    // Derive and check the pool PDA.
    let (expected_pool, bump) =
        Pubkey::find_program_address(&[POOL_SEED, payer.key.as_ref()], program_id);
    if expected_pool != *pool_account.key {
        return Err(MirrorPoolError::InvalidPoolAddress.into());
    }
    if pool_account.owner == program_id && !pool_account.data_is_empty() {
        return Err(MirrorPoolError::AlreadyInitialized.into());
    }

    // Create the account, signed by the pool PDA.
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(PoolConfig::LEN);
    invoke_signed(
        &create_account_ix(
            payer.key,
            pool_account.key,
            lamports,
            PoolConfig::LEN as u64,
            program_id,
        ),
        &[payer.clone(), pool_account.clone(), system_program.clone()],
        &[&[POOL_SEED, payer.key.as_ref(), &[bump]]],
    )?;

    // Initialize in place — the account buffer is the storage, so the 3.4 KB
    // struct never touches the stack.
    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    config.initialize(payer.key.to_bytes(), bump, depth)?;

    msg!("mirror-pool: pool initialized (depth {})", depth);
    Ok(())
}

/// `Deposit`: insert a commitment leaf, advancing the tree and root history.
fn process_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    commitment: [u8; 32],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_iter)?;

    if pool_account.owner != program_id {
        return Err(MirrorPoolError::InvalidAccountOwner.into());
    }

    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    if config.is_initialized == 0 {
        return Err(MirrorPoolError::NotInitialized.into());
    }
    let index = config.insert(commitment)?;

    msg!("mirror-pool: deposit at leaf index {}", index);
    Ok(())
}

/// System-program `create_account` instruction.
///
/// `solana_program::system_instruction` is deprecated in favor of the
/// `solana-system-interface` crate, but it remains correct on solana-program
/// 2.x and avoids pulling an extra dependency; the deprecation is silenced here
/// only, at the single call site.
#[allow(deprecated)]
fn create_account_ix(
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> SolInstruction {
    solana_program::system_instruction::create_account(from, to, lamports, space, owner)
}
