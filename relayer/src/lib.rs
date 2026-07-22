//! mirror-pool relayer library: build and submit `execute_action` transactions
//! on behalf of members, paying the fee so the member's wallet never appears as
//! the fee payer (SPEC §4.4 — the relayer is core, not optional).
//!
//! The member (via the CLI) produces a [`RelayJob`] — a self-contained proof +
//! public inputs + action — and hands it to a relayer out of band. The relayer
//! assembles the transaction, signs it as the sole fee payer, and submits it.
//! Because the pool PDA is the on-chain actor and the relayer is the fee payer,
//! nothing in the landed transaction links back to the member.

use anyhow::{anyhow, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use mirror_pool_program::action::{SELECTOR_NOOP, SELECTOR_TRANSFER};
use mirror_pool_program::instruction::Instruction as PoolIx;
use mirror_pool_program::verifier::{NUM_PUBLIC_INPUTS, PROOF_LEN};
use mirror_pool_program::{state::POOL_SEED, NULLIFIER_SEED};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Signature, Signer},
    transaction::Transaction,
};

/// A self-contained relay request: everything needed to submit one
/// `execute_action`, and nothing that identifies the member. The action's
/// trailing accounts are derived from the selector/params, so the job carries
/// no member-linkable account data.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct RelayJob {
    pub proof: [u8; PROOF_LEN],
    pub public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
    pub action_selector: u8,
    pub action_params: Vec<u8>,
}

impl RelayJob {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read job {}", path.display()))?;
        Self::try_from_slice(&bytes).map_err(|e| anyhow!("decode job: {e}"))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let bytes = borsh::to_vec(self).map_err(|e| anyhow!("encode job: {e}"))?;
        std::fs::write(path, bytes).with_context(|| format!("write job {}", path.display()))?;
        Ok(())
    }

    /// The nullifier hash this job will spend (public input #1).
    pub fn nullifier_hash(&self) -> [u8; 32] {
        self.public_inputs[1]
    }
}

/// Derive the pool config PDA for `authority`.
pub fn pool_pda(program_id: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[POOL_SEED, authority.as_ref()], program_id).0
}

/// Build the `execute_action` instruction for `job`, paid by `fee_payer`.
pub fn build_execute_ix(
    program_id: &Pubkey,
    pool: &Pubkey,
    fee_payer: &Pubkey,
    job: &RelayJob,
) -> Result<Instruction> {
    let (nullifier_pda, _bump) =
        Pubkey::find_program_address(&[NULLIFIER_SEED, &job.nullifier_hash()], program_id);

    let data = PoolIx::ExecuteAction {
        proof: job.proof,
        public_inputs: job.public_inputs,
        action_selector: job.action_selector,
        action_params: job.action_params.clone(),
    }
    .pack()
    .map_err(|e| anyhow!("pack execute_action: {e:?}"))?;

    let mut accounts = vec![
        AccountMeta::new(*pool, false),
        AccountMeta::new(nullifier_pda, false),
        AccountMeta::new(*fee_payer, true), // relayer pays the fee — never the member
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    // Trailing (action-specific) accounts, derived from the selector/params.
    accounts.extend(trailing_accounts(program_id, job)?);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Derive the action's trailing accounts (index 4 on) from the job. Adding a new
/// action adds a case here (mirrors `program::action::dispatch`).
fn trailing_accounts(program_id: &Pubkey, job: &RelayJob) -> Result<Vec<AccountMeta>> {
    match job.action_selector {
        SELECTOR_NOOP => Ok(vec![AccountMeta::new_readonly(*program_id, false)]),
        SELECTOR_TRANSFER => {
            if job.action_params.len() < 40 {
                return Err(anyhow!("transfer params too short"));
            }
            let recipient = Pubkey::new_from_array(
                job.action_params[8..40]
                    .try_into()
                    .map_err(|_| anyhow!("bad recipient"))?,
            );
            Ok(vec![AccountMeta::new(recipient, false)])
        }
        s => Err(anyhow!("unknown action selector {s}")),
    }
}

/// Submit one job, signed and paid for by `relayer`. Returns the signature.
pub fn relay(
    rpc: &RpcClient,
    relayer: &dyn Signer,
    program_id: &Pubkey,
    pool: &Pubkey,
    job: &RelayJob,
) -> Result<Signature> {
    let ix = build_execute_ix(program_id, pool, &relayer.pubkey(), job)?;
    let blockhash = rpc
        .get_latest_blockhash()
        .context("fetch recent blockhash")?;
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&relayer.pubkey()), &[relayer], blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .context("submit execute_action")
}
