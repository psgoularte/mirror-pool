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
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// Selector for the no-op action (also feeds the action binding).
pub const SELECTOR_NOOP: u8 = 0;

/// The action-binding value the proof must commit to for `selector`.
///
/// `action_binding = Poseidon(be32(selector))`. Binding the selector into the
/// proof stops a proof authorized for one action from being replayed for
/// another. (Actions with parameters extend this to hash the params too;
/// milestone 5's no-op takes none.) Mirrors `common::poseidon::action_binding`.
pub fn action_binding(selector: u8) -> Result<[u8; 32], ProgramError> {
    let mut field = [0u8; 32];
    field[31] = selector; // big-endian 32-byte encoding of the small integer
    let h = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&field])
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

/// Resolve a selector to its [`Action`]. The single extension point: a new
/// integration adds one arm here plus an `impl Action`.
pub fn dispatch(selector: u8) -> Result<Box<dyn Action>, ProgramError> {
    match selector {
        SELECTOR_NOOP => Ok(Box::new(NoOpAction)),
        _ => Err(MirrorPoolError::UnknownAction.into()),
    }
}
