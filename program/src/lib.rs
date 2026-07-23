//! `mirror-pool` on-chain program (native `solana-program`, no Anchor).
//!
//! Milestones fill in the modules over time:
//!
//! * M3 — Groth16 membership-proof verification via `groth16-solana`.
//! * M4 — incremental Merkle tree + `deposit` with a root-history buffer.
//! * M5 (here) — nullifier set + `execute_action` gated by the membership
//!   proof, with a PDA-signed CPI to the action (`ExecuteAction`, `NoOpAction`).
//! * M6 — epochs + one real protocol integration.
//! * M7 — compliance: viewing keys / selective disclosure + screening hook.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::Instruction as SolInstruction,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

pub mod action;
pub mod error;
pub mod instruction;
pub mod merkle;
pub mod state;
pub mod verifier;

use action::{ActionContext, SELECTOR_NOOP};
use error::MirrorPoolError;
use instruction::Instruction;
use state::{PoolConfig, POOL_SEED};
use verifier::{ParsedVerifyingKey, NUM_PUBLIC_INPUTS, PROOF_LEN};

/// PDA seed prefix for a per-nullifier marker account.
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

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
        #[cfg(feature = "bench")]
        Instruction::VerifyMembership {
            proof,
            public_inputs,
        } => process_verify_membership(accounts, &proof, &public_inputs),
        Instruction::InitializePool {
            depth,
            k_min,
            verifying_key,
            entry_fee,
        } => process_initialize_pool(
            program_id,
            accounts,
            depth,
            k_min,
            entry_fee,
            &verifying_key,
        ),
        Instruction::Deposit { commitment } => process_deposit(program_id, accounts, commitment),
        Instruction::ExecuteAction {
            proof,
            public_inputs,
            action_selector,
            action_params,
        } => process_execute_action(
            program_id,
            accounts,
            &proof,
            &public_inputs,
            action_selector,
            &action_params,
        ),
        Instruction::NoOpAction => process_noop_action(accounts),
        Instruction::OpenEpoch => process_epoch(program_id, accounts, true),
        Instruction::CloseEpoch => process_epoch(program_id, accounts, false),
        Instruction::SetScreeningAuthority { authority } => {
            process_set_screening_authority(program_id, accounts, authority)
        }
        Instruction::RegisterViewingKey {
            commitment,
            auditor,
            sealed_secret,
        } => process_register_viewing_key(program_id, accounts, commitment, auditor, sealed_secret),
    }
}

/// `VerifyMembership`: verify a proof against a VK supplied in the first
/// account. **Benchmark-only** (`bench` feature) — compiled out of the deployed
/// program, so its unchecked VK-account read is never part of production surface.
#[cfg(feature = "bench")]
fn process_verify_membership(
    accounts: &[AccountInfo],
    proof: &[u8; PROOF_LEN],
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vk_account = next_account_info(account_iter)?;
    let vk_data = vk_account.try_borrow_data()?;
    let vk = ParsedVerifyingKey::parse(&vk_data)?;
    verifier::verify_membership(&vk, proof, public_inputs)?;
    msg!("mirror-pool: membership proof verified");
    Ok(())
}

/// `InitializePool`: create the pool-config PDA (`["pool", authority]`) with an
/// empty tree and the circuit's verifying key.
fn process_initialize_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    depth: u8,
    k_min: u64,
    entry_fee: u64,
    verifying_key: &[u8; verifier::VK_SERIALIZED_LEN],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;
    let pool_account = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }

    let (expected_pool, bump) =
        Pubkey::find_program_address(&[POOL_SEED, payer.key.as_ref()], program_id);
    if expected_pool != *pool_account.key {
        return Err(MirrorPoolError::InvalidPoolAddress.into());
    }
    if pool_account.owner == program_id && !pool_account.data_is_empty() {
        return Err(MirrorPoolError::AlreadyInitialized.into());
    }

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

    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    config.initialize(
        payer.key.to_bytes(),
        bump,
        depth,
        k_min,
        entry_fee,
        verifying_key,
    )?;

    msg!(
        "mirror-pool: pool initialized (depth {}, k_min {}, entry_fee {})",
        depth,
        k_min,
        entry_fee
    );
    Ok(())
}

/// `Deposit`: insert a commitment leaf, advancing the tree and root history.
///
/// Accounts (in order): `[pool (writable), <screener (signer)>,
/// <depositor (signer, writable), system_program>]`. The screener is required
/// only when screening is enabled; the depositor + system_program are required
/// only when the pool charges a non-zero `entry_fee`. With screening off and
/// `entry_fee = 0` the account list is just `[pool]` — identical to the original
/// permissionless deposit.
///
/// The entry fee is the anti-Sybil mitigation: when set, every commitment costs
/// `entry_fee` lamports, paid into the pool PDA (the fee vault) by the depositor.
/// This raises the *cost* of inflating the anonymity set with self-controlled
/// commitments; it does not make Sybil inflation impossible.
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

    // Read the fee/screening config without holding the borrow across the CPI.
    let (entry_fee, screening_enabled, screening_authority) = {
        let data = pool_account.try_borrow_data()?;
        let config = PoolConfig::load(&data)?;
        if config.is_initialized == 0 {
            return Err(MirrorPoolError::NotInitialized.into());
        }
        (
            config.entry_fee(),
            config.screening_enabled(),
            config.screening_authority,
        )
    };

    // Deposit-screening hook (off by default).
    if screening_enabled {
        let screener = next_account_info(account_iter)
            .map_err(|_| ProgramError::from(MirrorPoolError::ScreeningRequired))?;
        if screener.key.to_bytes() != screening_authority {
            return Err(MirrorPoolError::ScreeningRequired.into());
        }
        if !screener.is_signer {
            return Err(MirrorPoolError::ScreeningRequired.into());
        }
    }

    // Anti-Sybil entry fee (off when `entry_fee == 0`). The depositor pays the
    // fee into the pool PDA; underpayment (insufficient balance) is a loud,
    // typed rejection. No borrow of the pool data is held across the transfer.
    if entry_fee > 0 {
        let depositor = next_account_info(account_iter)
            .map_err(|_| ProgramError::from(MirrorPoolError::EntryFeeUnpaid))?;
        let system_program = next_account_info(account_iter)
            .map_err(|_| ProgramError::from(MirrorPoolError::MissingAccount))?;
        if !depositor.is_signer {
            return Err(MirrorPoolError::MissingSignature.into());
        }
        if depositor.lamports() < entry_fee {
            return Err(MirrorPoolError::EntryFeeUnpaid.into());
        }
        invoke(
            &transfer_ix(depositor.key, pool_account.key, entry_fee),
            &[
                depositor.clone(),
                pool_account.clone(),
                system_program.clone(),
            ],
        )?;
    }

    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    let index = config.insert(commitment)?;
    msg!("mirror-pool: deposit at leaf index {}", index);
    Ok(())
}

/// `SetScreeningAuthority`: enable/disable the deposit-screening hook
/// (authority only). Accounts: `[pool (writable), authority (signer)]`.
fn process_set_screening_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_authority: [u8; 32],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    if pool_account.owner != program_id {
        return Err(MirrorPoolError::InvalidAccountOwner.into());
    }
    if !authority.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }
    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    if config.is_initialized == 0 {
        return Err(MirrorPoolError::NotInitialized.into());
    }
    if config.authority != authority.key.to_bytes() {
        return Err(MirrorPoolError::NotPoolAuthority.into());
    }
    config.screening_authority = new_authority;
    msg!("mirror-pool: screening authority updated");
    Ok(())
}

/// `RegisterViewingKey`: create a persistent selective-disclosure record at the
/// PDA `["viewing", commitment]`. Accounts:
/// `[payer (signer, writable), record (writable), system_program]`.
fn process_register_viewing_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    commitment: [u8; 32],
    auditor: [u8; 32],
    sealed_secret: Vec<u8>,
) -> ProgramResult {
    if sealed_secret.len() > state::DisclosureRecord::MAX_SEALED_LEN {
        return Err(MirrorPoolError::InvalidInstructionData.into());
    }
    let account_iter = &mut accounts.iter();
    let payer = next_account_info(account_iter)?;
    let record_account = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    if !payer.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }
    let (expected, bump) =
        Pubkey::find_program_address(&[state::VIEWING_SEED, &commitment], program_id);
    if expected != *record_account.key {
        return Err(MirrorPoolError::InvalidPoolAddress.into());
    }
    if record_account.owner == program_id && !record_account.data_is_empty() {
        return Err(MirrorPoolError::AlreadyInitialized.into());
    }

    let record = state::DisclosureRecord {
        commitment,
        auditor,
        sealed_secret,
    };
    let len = record.serialized_len();
    let rent = Rent::get()?;
    invoke_signed(
        &create_account_ix(
            payer.key,
            record_account.key,
            rent.minimum_balance(len),
            len as u64,
            program_id,
        ),
        &[
            payer.clone(),
            record_account.clone(),
            system_program.clone(),
        ],
        &[&[state::VIEWING_SEED, &commitment, &[bump]]],
    )?;

    let mut data = record_account.try_borrow_mut_data()?;
    borsh::to_writer(&mut data[..], &record)
        .map_err(|_| ProgramError::from(MirrorPoolError::InvalidInstructionData))?;
    msg!("mirror-pool: viewing-key disclosure registered");
    Ok(())
}

/// `ExecuteAction`: the protocol's core. Verify the membership proof, enforce
/// epoch/root/action-binding, mark the nullifier as spent for this epoch, then
/// execute the action via a PDA-signed CPI.
///
/// Account layout: `[pool, nullifier_pda, fee_payer(signer), system_program,
/// <action accounts…>]`. The action accounts (index 4 on) start with the CPI
/// target program; for the no-op that is this program itself.
fn process_execute_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8; PROOF_LEN],
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
    action_selector: u8,
    action_params: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_iter)?;
    let nullifier_account = next_account_info(account_iter)?;
    let fee_payer = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    if !fee_payer.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }
    if pool_account.owner != program_id {
        return Err(MirrorPoolError::InvalidAccountOwner.into());
    }

    let merkle_root = &public_inputs[0];
    let nullifier_hash = &public_inputs[1];
    let epoch_id = &public_inputs[2];
    let action_binding = &public_inputs[3];

    // --- Verify everything against the pool, then drop the borrow before the
    // CPI (which needs to touch the pool account again). ---
    let (authority, bump) = {
        let data = pool_account.try_borrow_data()?;
        let config = PoolConfig::load(&data)?;
        if config.is_initialized == 0 {
            return Err(MirrorPoolError::NotInitialized.into());
        }
        // Epoch must be open, and the proof must target it — this forces
        // actions to cluster inside a shared window (crowd synchronization).
        if config.epoch_active == 0 {
            return Err(MirrorPoolError::EpochNotActive.into());
        }
        if *epoch_id != epoch_to_bytes(config.current_epoch()) {
            return Err(MirrorPoolError::EpochMismatch.into());
        }
        // Minimum anonymity set: refuse to act unless the on-chain lower bound
        // (members not yet acted this epoch) is at least k_min. This turns the
        // single-action-window risk into an enforced invariant, not a warning.
        if config.anonymity_lower_bound() < config.k_min() {
            return Err(MirrorPoolError::AnonymitySetTooSmall.into());
        }
        // Root: must be a known recent root (survives concurrent deposits).
        if !config.is_known_root(merkle_root) {
            return Err(MirrorPoolError::UnknownRoot.into());
        }
        // Action binding: the proof must authorize exactly this action AND its
        // parameters (amount, recipient, …).
        if *action_binding != action::action_binding(action_selector, action_params)? {
            return Err(MirrorPoolError::ActionBindingMismatch.into());
        }
        // The proof itself.
        let vk = ParsedVerifyingKey::parse(&config.verifying_key)?;
        verifier::verify_membership(&vk, proof, public_inputs)?;
        (config.authority, config.bump)
    };

    // --- Nullifier: reject reuse, then create the marker account. ---
    // The seed is scoped to the pool (`["nullifier", pool, hash]`) so a nullifier
    // spent in one pool cannot collide with or grief another pool under the same
    // program.
    let pool_key = pool_account.key.to_bytes();
    let (expected_nullifier, null_bump) =
        Pubkey::find_program_address(&[NULLIFIER_SEED, &pool_key, nullifier_hash], program_id);
    if expected_nullifier != *nullifier_account.key {
        return Err(MirrorPoolError::InvalidNullifierAddress.into());
    }
    if nullifier_account.owner == program_id && !nullifier_account.data_is_empty() {
        return Err(MirrorPoolError::NullifierAlreadyUsed.into());
    }
    let rent = Rent::get()?;
    invoke_signed(
        &create_account_ix(
            fee_payer.key,
            nullifier_account.key,
            rent.minimum_balance(1),
            1,
            program_id,
        ),
        &[
            fee_payer.clone(),
            nullifier_account.clone(),
            system_program.clone(),
        ],
        &[&[NULLIFIER_SEED, &pool_key, nullifier_hash, &[null_bump]]],
    )?;
    nullifier_account.try_borrow_mut_data()?[0] = 1;

    // Record the action for the per-epoch anonymity-set accounting (committed
    // together with the nullifier, before the CPI).
    {
        let mut data = pool_account.try_borrow_mut_data()?;
        PoolConfig::load_mut(&mut data)?.record_action();
    }

    // --- Execute the action, signed by the pool PDA. ---
    let pool_seeds: &[&[u8]] = &[POOL_SEED, &authority, core::slice::from_ref(&bump)];
    let ctx = ActionContext {
        program_id,
        pool: pool_account,
        pool_seeds,
        accounts: &accounts[4..],
        params: action_params,
    };
    let action = action::dispatch(action_selector)?;
    action.execute(&ctx)?;

    msg!(
        "mirror-pool: action {} executed (nullifier spent)",
        action_selector
    );
    Ok(())
}

/// `NoOpAction`: the no-op action's CPI target. Valid only when invoked by the
/// pool PDA as a signer — proving the pool, not the member, is the actor.
fn process_noop_action(accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_iter)?;
    if !pool_account.is_signer {
        return Err(MirrorPoolError::UnauthorizedActor.into());
    }
    msg!("mirror-pool: no-op action ran (selector {})", SELECTOR_NOOP);
    Ok(())
}

/// `OpenEpoch` / `CloseEpoch` crank: advance or close the epoch window. Only the
/// pool authority may crank. Accounts: `[pool (writable), authority (signer)]`.
fn process_epoch(program_id: &Pubkey, accounts: &[AccountInfo], open: bool) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let pool_account = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;

    if pool_account.owner != program_id {
        return Err(MirrorPoolError::InvalidAccountOwner.into());
    }
    if !authority.is_signer {
        return Err(MirrorPoolError::MissingSignature.into());
    }

    let mut data = pool_account.try_borrow_mut_data()?;
    let config = PoolConfig::load_mut(&mut data)?;
    if config.is_initialized == 0 {
        return Err(MirrorPoolError::NotInitialized.into());
    }
    if config.authority != authority.key.to_bytes() {
        return Err(MirrorPoolError::NotPoolAuthority.into());
    }

    if open {
        let epoch = config.open_epoch()?;
        msg!("mirror-pool: epoch {} opened", epoch);
    } else {
        config.close_epoch()?;
        msg!("mirror-pool: epoch {} closed", config.current_epoch());
    }
    Ok(())
}

/// 32-byte big-endian encoding of an epoch id (matches `Fr::from(epoch)`).
fn epoch_to_bytes(epoch: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&epoch.to_be_bytes());
    b
}

/// System-program `create_account` instruction.
///
/// `solana_program::system_instruction` is deprecated in favor of the
/// `solana-system-interface` crate, but it remains correct on solana-program
/// 2.x and avoids an extra dependency; the deprecation is silenced only here.
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

/// System-program `transfer` instruction (for the anti-Sybil entry fee). Same
/// deprecation note as [`create_account_ix`].
#[allow(deprecated)]
fn transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> SolInstruction {
    solana_program::system_instruction::transfer(from, to, lamports)
}
