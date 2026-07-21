//! Convert arkworks Groth16 keys and proofs into the byte layout the on-chain
//! verifier (`groth16-solana`, via the `alt_bn128` syscalls) consumes.
//!
//! Three quirks the SPEC calls out, handled explicitly here:
//!
//! 1. **Endianness.** arkworks stores field limbs little-endian; the syscalls
//!    want each 32-byte coordinate big-endian. We serialize coordinates via
//!    `into_bigint().to_bytes_be()` directly, so the output is big-endian by
//!    construction (no post-hoc reversal to get wrong).
//! 2. **G2 coordinate order.** The `alt_bn128` precompile encodes an `Fq2`
//!    coordinate imaginary-part-first (`c1` then `c0`), the opposite of
//!    arkworks' in-memory `(c0, c1)`. `g2_to_bytes` emits `c1 || c0`.
//! 3. **`proof_a` negation.** The verifier checks `e(-A, B)·e(α,β)·…`, so the
//!    A point is negated before encoding.
//!
//! The `verifies_through_groth16_solana` test constructs a real proof, converts
//! it here, and runs it through `groth16-solana`'s verifier — so the layout is
//! validated end-to-end, not asserted by eye.

use crate::error::{CircuitError, Result};
use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use mirror_pool_common::FIELD_BYTES;
use std::ops::Neg;

/// Encoded G1 point: `x_be || y_be`.
pub const G1_LEN: usize = 2 * FIELD_BYTES;
/// Encoded G2 point: `x.c1_be || x.c0_be || y.c1_be || y.c0_be`.
pub const G2_LEN: usize = 4 * FIELD_BYTES;

fn fq_be(f: &Fq) -> [u8; FIELD_BYTES] {
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; FIELD_BYTES];
    // BN254 base field fits in 32 bytes; to_bytes_be is already that wide.
    out.copy_from_slice(&be);
    out
}

/// Encode a G1 affine point as `x_be || y_be` (64 bytes).
pub fn g1_to_bytes(p: &G1Affine) -> [u8; G1_LEN] {
    let mut out = [0u8; G1_LEN];
    out[..FIELD_BYTES].copy_from_slice(&fq_be(&p.x));
    out[FIELD_BYTES..].copy_from_slice(&fq_be(&p.y));
    out
}

/// Encode a G2 affine point as `x.c1 || x.c0 || y.c1 || y.c0` (128 bytes),
/// imaginary part first per the `alt_bn128` convention.
pub fn g2_to_bytes(p: &G2Affine) -> [u8; G2_LEN] {
    let mut out = [0u8; G2_LEN];
    out[0..FIELD_BYTES].copy_from_slice(&fq_be(&p.x.c1));
    out[FIELD_BYTES..2 * FIELD_BYTES].copy_from_slice(&fq_be(&p.x.c0));
    out[2 * FIELD_BYTES..3 * FIELD_BYTES].copy_from_slice(&fq_be(&p.y.c1));
    out[3 * FIELD_BYTES..].copy_from_slice(&fq_be(&p.y.c0));
    out
}

/// A proof in the on-chain byte layout. `proof_a` is already negated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaProof {
    pub proof_a: [u8; G1_LEN],
    pub proof_b: [u8; G2_LEN],
    pub proof_c: [u8; G1_LEN],
}

impl SolanaProof {
    /// Flat 256-byte encoding: `a || b || c`.
    pub fn to_bytes(&self) -> [u8; 2 * G1_LEN + G2_LEN] {
        let mut out = [0u8; 2 * G1_LEN + G2_LEN];
        out[..G1_LEN].copy_from_slice(&self.proof_a);
        out[G1_LEN..G1_LEN + G2_LEN].copy_from_slice(&self.proof_b);
        out[G1_LEN + G2_LEN..].copy_from_slice(&self.proof_c);
        out
    }
}

/// Convert an arkworks proof, negating `A` as the verifier expects.
pub fn proof_to_solana(proof: &Proof<Bn254>) -> SolanaProof {
    SolanaProof {
        proof_a: g1_to_bytes(&proof.a.neg()),
        proof_b: g2_to_bytes(&proof.b),
        proof_c: g1_to_bytes(&proof.c),
    }
}

/// A verifying key in the on-chain byte layout. `ic` has `num_public + 1`
/// entries. Owned (not borrowed) so it can be embedded and parsed on-chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaVerifyingKey {
    pub alpha_g1: [u8; G1_LEN],
    pub beta_g2: [u8; G2_LEN],
    pub gamma_g2: [u8; G2_LEN],
    pub delta_g2: [u8; G2_LEN],
    pub ic: Vec<[u8; G1_LEN]>,
}

/// Fixed-size header of a serialized [`SolanaVerifyingKey`] before the IC list.
const VK_HEADER_LEN: usize = G1_LEN + 3 * G2_LEN;

impl SolanaVerifyingKey {
    /// Number of public inputs this key is for (`ic.len() - 1`).
    pub fn num_public_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }

    /// Flat encoding: `alpha || beta || gamma || delta || (ic_len as u8) || ic…`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VK_HEADER_LEN + 1 + self.ic.len() * G1_LEN);
        out.extend_from_slice(&self.alpha_g1);
        out.extend_from_slice(&self.beta_g2);
        out.extend_from_slice(&self.gamma_g2);
        out.extend_from_slice(&self.delta_g2);
        out.push(self.ic.len() as u8);
        for point in &self.ic {
            out.extend_from_slice(point);
        }
        out
    }

    /// Parse the flat encoding produced by [`Self::to_bytes`]. Fails loudly on
    /// any length mismatch rather than reading out of bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bad = |what: &str| CircuitError::Serialize(format!("vk decode: {what}"));
        if bytes.len() < VK_HEADER_LEN + 1 {
            return Err(bad("truncated header"));
        }
        let mut off = 0usize;
        let mut take = |n: usize| -> std::result::Result<&[u8], CircuitError> {
            let end = off + n;
            let s = bytes.get(off..end).ok_or_else(|| bad("out of bounds"))?;
            off = end;
            Ok(s)
        };
        let alpha_g1 = take(G1_LEN)?.try_into().map_err(|_| bad("alpha"))?;
        let beta_g2 = take(G2_LEN)?.try_into().map_err(|_| bad("beta"))?;
        let gamma_g2 = take(G2_LEN)?.try_into().map_err(|_| bad("gamma"))?;
        let delta_g2 = take(G2_LEN)?.try_into().map_err(|_| bad("delta"))?;
        let ic_len = take(1)?[0] as usize;
        let mut ic = Vec::with_capacity(ic_len);
        for _ in 0..ic_len {
            ic.push(take(G1_LEN)?.try_into().map_err(|_| bad("ic point"))?);
        }
        if off != bytes.len() {
            return Err(bad("trailing bytes"));
        }
        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }
}

/// Convert an arkworks verifying key to the on-chain layout.
pub fn vk_to_solana(vk: &VerifyingKey<Bn254>) -> SolanaVerifyingKey {
    SolanaVerifyingKey {
        alpha_g1: g1_to_bytes(&vk.alpha_g1),
        beta_g2: g2_to_bytes(&vk.beta_g2),
        gamma_g2: g2_to_bytes(&vk.gamma_g2),
        delta_g2: g2_to_bytes(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(g1_to_bytes).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{build_witness, prove, setup, PublicInputs};
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
    use mirror_pool_common::merkle::MerkleTree;
    use mirror_pool_common::poseidon;
    use mirror_pool_common::TREE_DEPTH;

    fn run_solana_verifier(
        vk: &SolanaVerifyingKey,
        proof: &SolanaProof,
        public_inputs: &[[u8; 32]; 4],
    ) -> std::result::Result<(), groth16_solana::errors::Groth16Error> {
        let g16_vk = Groth16Verifyingkey {
            nr_pubinputs: vk.num_public_inputs(),
            vk_alpha_g1: vk.alpha_g1,
            vk_beta_g2: vk.beta_g2,
            vk_gamme_g2: vk.gamma_g2,
            vk_delta_g2: vk.delta_g2,
            vk_ic: &vk.ic,
        };
        let mut verifier = Groth16Verifier::<4>::new(
            &proof.proof_a,
            &proof.proof_b,
            &proof.proof_c,
            public_inputs,
            &g16_vk,
        )?;
        verifier.verify()
    }

    fn sample_proof() -> (SolanaVerifyingKey, SolanaProof, [[u8; 32]; 4]) {
        let mut rng = StdRng::seed_from_u64(0xABCD);
        let (pk, vk) = setup(TREE_DEPTH, &mut rng).unwrap();

        let mut tree = MerkleTree::new(TREE_DEPTH);
        let mut secret = Fr::from(0u64);
        for i in 0..6u64 {
            let s = Fr::rand(&mut rng);
            if i == 3 {
                secret = s;
            }
            tree.insert(poseidon::commitment(s)).unwrap();
        }
        let path = tree.proof(3).unwrap();
        let assignment =
            build_witness(secret, &path, Fr::from(77u64), Fr::from(0xDEADu64)).unwrap();
        let public_inputs: PublicInputs = assignment.public_inputs.clone();
        let proof = prove(&pk, assignment.circuit, &mut rng).unwrap();

        let sol_vk = vk_to_solana(&vk);
        let sol_proof = proof_to_solana(&proof);
        let pi_bytes = public_inputs.to_bytes();
        let pi: [[u8; 32]; 4] = [pi_bytes[0], pi_bytes[1], pi_bytes[2], pi_bytes[3]];
        (sol_vk, sol_proof, pi)
    }

    #[test]
    fn verifies_through_groth16_solana() {
        let (vk, proof, pi) = sample_proof();
        assert_eq!(vk.ic.len(), 5, "4 public inputs + 1");
        run_solana_verifier(&vk, &proof, &pi).expect("arkworks proof must verify on-chain layout");
    }

    #[test]
    fn tampered_public_input_is_rejected() {
        let (vk, proof, mut pi) = sample_proof();
        // Flip the action-binding public input; verification must fail.
        pi[3][31] ^= 0x01;
        assert!(run_solana_verifier(&vk, &proof, &pi).is_err());
    }

    #[test]
    fn vk_bytes_roundtrip() {
        let (vk, _proof, _pi) = sample_proof();
        let bytes = vk.to_bytes();
        assert_eq!(SolanaVerifyingKey::from_bytes(&bytes).unwrap(), vk);
    }
}
