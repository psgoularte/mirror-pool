//! On-chain Groth16 membership-proof verification via `groth16-solana`
//! (the `alt_bn128` syscalls).
//!
//! This module is byte-oriented on purpose: it never links arkworks. The
//! verifying key arrives as the flat layout produced by
//! `mirror_pool_circuit::solana::SolanaVerifyingKey::to_bytes`, the proof as the
//! 256-byte `a || b || c` blob (with `a` already negated), and public inputs as
//! big-endian 32-byte limbs. Keeping it byte-only is what lets verification run
//! inside the compute budget on BPF.

use crate::error::MirrorPoolError;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_program::program_error::ProgramError;

/// Number of public inputs to the membership circuit
/// (`merkle_root, nullifier_hash, epoch_id, action_binding`).
pub const NUM_PUBLIC_INPUTS: usize = 4;

const G1_LEN: usize = 64;
const G2_LEN: usize = 128;
/// Flat proof length: `a(64) || b(128) || c(64)`.
pub const PROOF_LEN: usize = 2 * G1_LEN + G2_LEN;
const VK_HEADER_LEN: usize = G1_LEN + 3 * G2_LEN;

/// A verifying key parsed from its flat byte layout, owning the IC points so the
/// borrowed `Groth16Verifyingkey` can reference them.
pub struct ParsedVerifyingKey {
    alpha_g1: [u8; G1_LEN],
    beta_g2: [u8; G2_LEN],
    gamma_g2: [u8; G2_LEN],
    delta_g2: [u8; G2_LEN],
    ic: Vec<[u8; G1_LEN]>,
}

impl ParsedVerifyingKey {
    /// Parse the flat VK layout:
    /// `alpha(64) || beta(128) || gamma(128) || delta(128) || ic_len(1) || ic…`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProgramError> {
        fn err() -> ProgramError {
            ProgramError::from(MirrorPoolError::InvalidVerifyingKey)
        }
        if bytes.len() < VK_HEADER_LEN + 1 {
            return Err(err());
        }
        let mut off = 0usize;
        let mut take = |n: usize| -> Result<&[u8], ProgramError> {
            let end = off.checked_add(n).ok_or_else(err)?;
            let s = bytes.get(off..end).ok_or_else(err)?;
            off = end;
            Ok(s)
        };
        let alpha_g1 = take(G1_LEN)?.try_into().map_err(|_| err())?;
        let beta_g2 = take(G2_LEN)?.try_into().map_err(|_| err())?;
        let gamma_g2 = take(G2_LEN)?.try_into().map_err(|_| err())?;
        let delta_g2 = take(G2_LEN)?.try_into().map_err(|_| err())?;
        let ic_len = take(1)?[0] as usize;
        // A membership VK must have exactly NUM_PUBLIC_INPUTS + 1 IC points.
        if ic_len != NUM_PUBLIC_INPUTS + 1 {
            return Err(err());
        }
        let mut ic = Vec::with_capacity(ic_len);
        for _ in 0..ic_len {
            ic.push(take(G1_LEN)?.try_into().map_err(|_| err())?);
        }
        if off != bytes.len() {
            return Err(err());
        }
        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    fn as_groth16(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: NUM_PUBLIC_INPUTS,
            vk_alpha_g1: self.alpha_g1,
            vk_beta_g2: self.beta_g2,
            vk_gamme_g2: self.gamma_g2,
            vk_delta_g2: self.delta_g2,
            vk_ic: &self.ic,
        }
    }
}

/// Verify a membership proof against a parsed verifying key.
///
/// Returns `Ok(())` iff the proof is valid for exactly these public inputs.
/// Any parse failure or a failed pairing returns a typed error — there is no
/// path that treats an unverifiable proof as valid.
pub fn verify_membership(
    vk: &ParsedVerifyingKey,
    proof: &[u8; PROOF_LEN],
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> Result<(), ProgramError> {
    let proof_a: &[u8; G1_LEN] = proof[..G1_LEN]
        .try_into()
        .map_err(|_| ProgramError::from(MirrorPoolError::InvalidProof))?;
    let proof_b: &[u8; G2_LEN] = proof[G1_LEN..G1_LEN + G2_LEN]
        .try_into()
        .map_err(|_| ProgramError::from(MirrorPoolError::InvalidProof))?;
    let proof_c: &[u8; G1_LEN] = proof[G1_LEN + G2_LEN..]
        .try_into()
        .map_err(|_| ProgramError::from(MirrorPoolError::InvalidProof))?;

    let g16_vk = vk.as_groth16();
    let mut verifier = Groth16Verifier::<NUM_PUBLIC_INPUTS>::new(
        proof_a,
        proof_b,
        proof_c,
        public_inputs,
        &g16_vk,
    )
    .map_err(|_| ProgramError::from(MirrorPoolError::InvalidProof))?;

    verifier
        .verify()
        .map_err(|_| ProgramError::from(MirrorPoolError::ProofVerificationFailed))
}
