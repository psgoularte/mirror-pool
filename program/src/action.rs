//! The `Action` abstraction — mirror-pool's extensibility seam.
//!
//! An action is "what the pool does on a member's behalf, signed by the pool
//! PDA." Adding a new protocol integration means implementing [`Action`] and
//! adding one arm to [`dispatch`] — not touching the proof/nullifier/epoch
//! machinery. The action executes via a **PDA-signed CPI**, so the on-chain
//! actor is the pool, never the member (the core unlinkability primitive).
//!
//! Milestone 5 ships the trivial [`NoOpAction`] (a self-CPI proving the PDA
//! signs) and a `no-op` selector. Milestone 6 adds a real integration and the
//! `ARCHITECTURE.md` extension guide.

use crate::error::MirrorPoolError;
use crate::instruction::Instruction as PoolInstruction;
use solana_poseidon::{hashv, Endianness, Parameters};
use solana_program::{
    account_info::AccountInfo,
    hash::hash as sha256,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

/// Selector for the no-op action (self-CPI; carries no params).
pub const SELECTOR_NOOP: u8 = 0;
/// Selector for the native SOL transfer action (real integration).
pub const SELECTOR_TRANSFER: u8 = 1;

/// Fixed denominations (lamports) the transfer action may move: 0.1, 1, and
/// 10 SOL. Restricting to a small set makes the amount **non-distinguishing** —
/// many members move the identical value, so the amount cannot re-link an
/// action to a member (Tornado-style). The amount is also proof-bound, so a
/// relayer cannot change it.
pub const DENOMINATIONS: [u64; 3] = [100_000_000, 1_000_000_000, 10_000_000_000];

/// Digest of an action's parameters, matching `common::poseidon::params_digest`.
/// Empty params → zero; otherwise SHA-256 with the top byte cleared (so the
/// value is a canonical BN254 field element with no reduction).
fn params_digest(params: &[u8]) -> [u8; 32] {
    if params.is_empty() {
        return [0u8; 32];
    }
    let mut d = sha256(params).to_bytes();
    d[0] = 0;
    d
}

/// The action-binding value the proof must commit to for `(selector, params)`.
///
/// `action_binding = Poseidon(be32(selector), params_digest(params))`. Binding
/// both the selector *and* the parameters into the proof stops a proof from
/// being replayed for a different action or different parameters (e.g. a
/// different transfer amount or recipient). Mirrors
/// `common::poseidon::action_binding`.
pub fn action_binding(selector: u8, params: &[u8]) -> Result<[u8; 32], ProgramError> {
    let mut sel = [0u8; 32];
    sel[31] = selector; // big-endian 32-byte encoding of the small integer
    let digest = params_digest(params);
    let h = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&sel, &digest])
        .map_err(|_| ProgramError::from(MirrorPoolError::PoseidonFailed))?;
    Ok(h.to_bytes())
}

/// Everything an action needs to perform its PDA-signed CPI.
pub struct ActionContext<'a, 'info> {
    /// This program's id (CPI target for the no-op; a real action targets its
    /// integration program, passed among `accounts`).
    pub program_id: &'a Pubkey,
    /// The pool PDA account — the CPI signer.
    pub pool: &'a AccountInfo<'info>,
    /// Signer seeds for the pool PDA (`["pool", authority, [bump]]`).
    pub pool_seeds: &'a [&'a [u8]],
    /// Accounts beyond the fixed execute_action set, for the action's CPI.
    pub accounts: &'a [AccountInfo<'info>],
    /// Action parameters (opaque to the framework).
    pub params: &'a [u8],
}

/// A protocol action executed by the pool PDA.
pub trait Action {
    /// Stable selector; must match the value bound into the proof.
    fn selector(&self) -> u8;
    /// Perform the action via one or more PDA-signed CPIs.
    fn execute(&self, ctx: &ActionContext) -> Result<(), ProgramError>;
}

/// The trivial action: a self-CPI into [`PoolInstruction::NoOpAction`] with the
/// pool PDA as signer. It carries no economic effect; its purpose is to prove
/// end-to-end that the pool PDA — not the member — signs the resulting
/// transaction.
pub struct NoOpAction;

impl Action for NoOpAction {
    fn selector(&self) -> u8 {
        SELECTOR_NOOP
    }

    fn execute(&self, ctx: &ActionContext) -> Result<(), ProgramError> {
        if !ctx.params.is_empty() {
            return Err(MirrorPoolError::InvalidInstructionData.into());
        }
        let ix = Instruction {
            program_id: *ctx.program_id,
            accounts: vec![AccountMeta::new_readonly(*ctx.pool.key, true)],
            data: PoolInstruction::NoOpAction.pack()?,
        };
        // invoke_signed needs the CPI's accounts (pool) plus the callee program
        // account (passed among `ctx.accounts`). The pool PDA signs via its
        // seeds — this is the unlinkability primitive.
        let mut infos = Vec::with_capacity(1 + ctx.accounts.len());
        infos.push(ctx.pool.clone());
        infos.extend_from_slice(ctx.accounts);
        invoke_signed(&ix, &infos, &[ctx.pool_seeds])?;
        msg!("mirror-pool: no-op action executed by pool PDA");
        Ok(())
    }
}

/// A real integration: disburse `amount` lamports from the pool PDA to a
/// recipient, on a member's behalf. The pool PDA is the actor, so an observer
/// cannot link the disbursement to the member who authorized it.
///
/// Parameters (40 bytes, bound into the proof): `amount: u64 (LE) ||
/// recipient: [u8; 32]`. The recipient account is passed as `ctx.accounts[0]`
/// and must match the bound key. Because the pool account is program-owned,
/// lamports are moved by direct balance arithmetic (the System program cannot
/// transfer out of a non-system-owned account); the pool is kept rent-exempt.
///
/// A CPI-based integration (a swap, a stake) implements this same trait but
/// calls `invoke_signed` into the venue program — see [`NoOpAction`] for the
/// PDA-signed CPI shape.
pub struct TransferAction;

impl TransferAction {
    pub const PARAMS_LEN: usize = 8 + 32;
}

impl Action for TransferAction {
    fn selector(&self) -> u8 {
        SELECTOR_TRANSFER
    }

    fn execute(&self, ctx: &ActionContext) -> Result<(), ProgramError> {
        if ctx.params.len() != Self::PARAMS_LEN {
            return Err(MirrorPoolError::InvalidInstructionData.into());
        }
        let amount = u64::from_le_bytes(
            ctx.params[..8]
                .try_into()
                .map_err(|_| ProgramError::from(MirrorPoolError::InvalidInstructionData))?,
        );
        // Amount privacy: only fixed denominations are allowed so the value is
        // not a distinguishing feature.
        if !DENOMINATIONS.contains(&amount) {
            return Err(MirrorPoolError::InvalidDenomination.into());
        }
        let recipient_key = Pubkey::new_from_array(
            ctx.params[8..40]
                .try_into()
                .map_err(|_| ProgramError::from(MirrorPoolError::InvalidInstructionData))?,
        );
        let recipient = ctx
            .accounts
            .first()
            .ok_or(ProgramError::from(MirrorPoolError::MissingAccount))?;
        if *recipient.key != recipient_key {
            return Err(MirrorPoolError::ActionBindingMismatch.into());
        }

        // The pool must remain rent-exempt after the disbursement.
        let rent = solana_program::rent::Rent::get()?;
        let min = rent.minimum_balance(crate::state::PoolConfig::LEN);
        let pool_balance = ctx.pool.lamports();
        let remaining = pool_balance
            .checked_sub(amount)
            .ok_or(ProgramError::from(MirrorPoolError::InsufficientPoolFunds))?;
        if remaining < min {
            return Err(MirrorPoolError::InsufficientPoolFunds.into());
        }

        // Move lamports out of the program-owned pool account directly.
        **ctx.pool.try_borrow_mut_lamports()? = remaining;
        **recipient.try_borrow_mut_lamports()? = recipient
            .lamports()
            .checked_add(amount)
            .ok_or(ProgramError::from(MirrorPoolError::InsufficientPoolFunds))?;

        msg!(
            "mirror-pool: transfer action moved {} lamports via pool PDA",
            amount
        );
        Ok(())
    }
}

/// Resolve a selector to its [`Action`]. The single extension point: a new
/// integration adds one arm here plus an `impl Action`.
pub fn dispatch(selector: u8) -> Result<Box<dyn Action>, ProgramError> {
    match selector {
        SELECTOR_NOOP => Ok(Box::new(NoOpAction)),
        SELECTOR_TRANSFER => Ok(Box::new(TransferAction)),
        _ => Err(MirrorPoolError::UnknownAction.into()),
    }
}
