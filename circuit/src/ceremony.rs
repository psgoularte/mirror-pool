//! Multi-contributor Phase-2 trusted setup (Groth16 / BN254), arkworks-native.
//!
//! Groth16 needs a per-circuit setup whose secret randomness ("toxic waste")
//! must be destroyed. A **single-party** setup is only as trustworthy as that
//! one party. This module implements a **multi-contributor Phase-2 ceremony**:
//! starting from a base setup, each contributor re-randomizes the `delta`
//! trapdoor with fresh entropy and publishes a proof-of-contribution. The
//! resulting key is secure **if at least one contributor discarded their
//! randomness** — the real Groth16 assurance.
//!
//! # What this re-randomizes (and what it does not)
//!
//! A Groth16 key has trapdoors `alpha, beta, gamma, delta, tau`. Phase-2
//! re-randomizes **`delta`** only (the standard division of labor:
//! `alpha, beta, tau` come from a universal **Phase-1** powers-of-tau). Each
//! contribution multiplies `delta` by a fresh secret `s`:
//!
//! * `pk.delta_g1 *= s`, `vk.delta_g2 *= s`;
//! * the `delta`-divided query vectors `pk.l_query`, `pk.h_query` are multiplied
//!   by `s⁻¹` (they were divided by `delta` at setup);
//! * everything else is unchanged.
//!
//! Each contribution publishes a Schnorr proof of knowledge of `s` (variable
//! base `prev_delta_g1`) and the pairing **same-ratio** check ties the `g1` and
//! `g2` updates to the *same* `s`. Verifying the chain from the base to the
//! committed key is fully public.
//!
//! **Honest scope.** This project's base is a single arkworks setup, so
//! `alpha, beta, gamma, tau` rest on that base's entropy being discarded; only
//! `delta` gets the multi-party guarantee. A production deployment adds a public
//! Phase-1 transcript so nothing rests on a single party. `docs/security.md`
//! states this plainly.

// NOTE: do not `use crate::error::Result` here — the `CanonicalSerialize`
// derive macro emits bare `Result<(), _>` which must resolve to `std`'s 2-arg
// Result, so we qualify our alias as `crate::error::Result` in signatures.
use crate::error::CircuitError;
use crate::prover::setup;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mirror_pool_common::TREE_DEPTH;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// A single Phase-2 contribution: the updated `delta` in both groups plus a
/// Schnorr proof of knowledge of the secret multiplier `s`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    /// `s · prev_delta_g1`.
    pub new_delta_g1: G1Affine,
    /// `s · prev_delta_g2`.
    pub new_delta_g2: G2Affine,
    /// Schnorr commitment `R = r · prev_delta_g1`.
    pub pok_r: G1Affine,
    /// Schnorr response `u = r + c·s`.
    pub pok_u: Fr,
}

/// The public ceremony transcript: the base `delta` (in both groups) and the
/// ordered contributions. Verifiable end-to-end by anyone.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Transcript {
    /// `delta_g1` of the base setup (before any contribution).
    pub base_delta_g1: G1Affine,
    /// `delta_g2` of the base setup.
    pub base_delta_g2: G2Affine,
    /// The ordered contributions.
    pub contributions: Vec<Contribution>,
}

impl Transcript {
    /// SHA-256 of the canonical serialization — the value the committed key is
    /// pinned by.
    pub fn hash(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .expect("transcript serializes");
        Sha256::digest(&bytes).into()
    }

    /// Serialize to bytes (compressed).
    pub fn to_bytes(&self) -> crate::error::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .map_err(|e| CircuitError::Serialize(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        Self::deserialize_compressed(bytes).map_err(|e| CircuitError::Serialize(e.to_string()))
    }
}

/// Fiat–Shamir challenge for the Schnorr PoK, bound to the statement.
fn challenge(prev_delta_g1: &G1Affine, new_delta_g1: &G1Affine, r: &G1Affine) -> Fr {
    let mut h = Sha256::new();
    h.update(b"mirror-pool/phase2/pok/v1");
    for p in [prev_delta_g1, new_delta_g1, r] {
        let mut b = Vec::new();
        p.serialize_compressed(&mut b).expect("point serializes");
        h.update(&b);
    }
    Fr::from_be_bytes_mod_order(&h.finalize())
}

/// Base setup — the "Phase-1" starting point. **Must** use fresh, discarded
/// entropy in a real ceremony (never a fixed seed).
pub fn base_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> crate::error::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    setup(TREE_DEPTH, rng)
}

/// Apply one Phase-2 contribution to `pk` (updating its `vk` too), returning the
/// public contribution. Uses fresh entropy from `rng` — the caller must discard
/// it for the contribution to add security.
pub fn contribute<R: RngCore + CryptoRng>(pk: &mut ProvingKey<Bn254>, rng: &mut R) -> Contribution {
    // Fresh, nonzero delta multiplier.
    let mut s = Fr::rand(rng);
    while s.is_zero() {
        s = Fr::rand(rng);
    }
    let s_inv = s.inverse().expect("nonzero");

    let prev_delta_g1 = pk.delta_g1;

    // delta *= s in both groups; delta-divided queries *= s⁻¹.
    pk.delta_g1 = (pk.delta_g1 * s).into_affine();
    pk.vk.delta_g2 = (pk.vk.delta_g2 * s).into_affine();
    for e in pk.l_query.iter_mut() {
        *e = (*e * s_inv).into_affine();
    }
    for e in pk.h_query.iter_mut() {
        *e = (*e * s_inv).into_affine();
    }

    // Schnorr PoK of s on base prev_delta_g1: R = r·B, u = r + c·s.
    let r = Fr::rand(rng);
    let pok_r = (prev_delta_g1 * r).into_affine();
    let c = challenge(&prev_delta_g1, &pk.delta_g1, &pok_r);
    let pok_u = r + c * s;

    Contribution {
        new_delta_g1: pk.delta_g1,
        new_delta_g2: pk.vk.delta_g2,
        pok_r,
        pok_u,
    }
}

/// Verify one contribution transforms `(prev_delta_g1, prev_delta_g2)` correctly:
/// the Schnorr PoK holds, the same `s` was used in both groups (same-ratio
/// pairing check), and `delta` actually changed.
pub fn verify_contribution(
    prev_delta_g1: &G1Affine,
    prev_delta_g2: &G2Affine,
    c: &Contribution,
) -> bool {
    if c.new_delta_g1 == *prev_delta_g1 {
        return false; // no-op contribution adds nothing
    }
    // Schnorr: u·B == R + c·new, with B = prev_delta_g1, new = s·B.
    let ch = challenge(prev_delta_g1, &c.new_delta_g1, &c.pok_r);
    let lhs = (*prev_delta_g1 * c.pok_u).into_affine();
    let rhs = (c.pok_r.into_group() + c.new_delta_g1 * ch).into_affine();
    if lhs != rhs {
        return false;
    }
    // Same-ratio: e(new_g1, prev_g2) == e(prev_g1, new_g2)  ⟺ same s in both.
    Bn254::pairing(c.new_delta_g1, *prev_delta_g2) == Bn254::pairing(*prev_delta_g1, c.new_delta_g2)
}

/// Verify the full transcript chain and that it produces `final_vk`'s `delta_g2`.
/// Returns `true` iff every contribution is valid and the composed `delta`
/// matches the committed verifying key.
pub fn verify_transcript(transcript: &Transcript, final_vk: &VerifyingKey<Bn254>) -> bool {
    if transcript.contributions.is_empty() {
        return false; // a "ceremony" with no contribution is a single-party setup
    }
    let mut prev_g1 = transcript.base_delta_g1;
    let mut prev_g2 = transcript.base_delta_g2;
    for c in &transcript.contributions {
        if !verify_contribution(&prev_g1, &prev_g2, c) {
            return false;
        }
        prev_g1 = c.new_delta_g1;
        prev_g2 = c.new_delta_g2;
    }
    prev_g2 == final_vk.delta_g2
}

/// Run a full ceremony: a base setup followed by `num_contributions`
/// independent contributions. Returns the final key and the public transcript.
/// `num_contributions` must be ≥ 1 (a real ceremony has at least one).
pub fn run_ceremony<R: RngCore + CryptoRng>(
    num_contributions: usize,
    rng: &mut R,
) -> crate::error::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>, Transcript)> {
    if num_contributions == 0 {
        return Err(CircuitError::Setup(
            "a ceremony needs at least one contribution".into(),
        ));
    }
    let (mut pk, _vk) = base_setup(rng)?;
    let base_delta_g1 = pk.delta_g1;
    let base_delta_g2 = pk.vk.delta_g2;

    let mut contributions = Vec::with_capacity(num_contributions);
    let mut prev_g1 = base_delta_g1;
    let mut prev_g2 = base_delta_g2;
    for _ in 0..num_contributions {
        let c = contribute(&mut pk, rng);
        // Sanity: each contribution must verify against the prior state.
        debug_assert!(verify_contribution(&prev_g1, &prev_g2, &c));
        prev_g1 = c.new_delta_g1;
        prev_g2 = c.new_delta_g2;
        contributions.push(c);
    }

    let vk = pk.vk.clone();
    let transcript = Transcript {
        base_delta_g1,
        base_delta_g2,
        contributions,
    };
    Ok((pk, vk, transcript))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{build_witness, prove, verify};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use mirror_pool_common::merkle::MerkleTree;
    use mirror_pool_common::poseidon::commitment;

    #[test]
    fn ceremony_key_still_proves_and_verifies() {
        // The strongest correctness gate: after 3 delta re-randomizations the
        // key must still produce and verify real membership proofs. A wrong
        // delta update would fail here.
        let mut rng = StdRng::seed_from_u64(0xCE12);
        let (pk, vk, transcript) = run_ceremony(3, &mut rng).unwrap();
        assert!(verify_transcript(&transcript, &vk));

        let mut tree = MerkleTree::new(TREE_DEPTH);
        let secret = Fr::from(42u64);
        tree.insert(commitment(secret)).unwrap();
        let path = tree.proof(0).unwrap();
        let a = build_witness(secret, &path, Fr::from(1u64), Fr::from(7u64)).unwrap();
        let public = a.public_inputs.clone();
        let proof = prove(&pk, a.circuit, &mut rng).unwrap();
        assert!(
            verify(&vk, &public, &proof).unwrap(),
            "ceremony key must verify"
        );
    }

    #[test]
    fn transcript_rejects_no_contributions() {
        let t = Transcript {
            base_delta_g1: G1Affine::generator(),
            base_delta_g2: G2Affine::generator(),
            contributions: vec![],
        };
        let mut rng = StdRng::seed_from_u64(1);
        let (_pk, vk, _t) = run_ceremony(1, &mut rng).unwrap();
        assert!(!verify_transcript(&t, &vk));
    }

    #[test]
    fn tampered_contribution_is_rejected() {
        let mut rng = StdRng::seed_from_u64(7);
        let (_pk, vk, mut transcript) = run_ceremony(2, &mut rng).unwrap();
        assert!(verify_transcript(&transcript, &vk));
        // Tamper the last contribution's response scalar.
        let last = transcript.contributions.last_mut().unwrap();
        last.pok_u += Fr::from(1u64);
        assert!(!verify_transcript(&transcript, &vk));
    }

    #[test]
    fn transcript_roundtrips() {
        let mut rng = StdRng::seed_from_u64(9);
        let (_pk, _vk, t) = run_ceremony(2, &mut rng).unwrap();
        let bytes = t.to_bytes().unwrap();
        let t2 = Transcript::from_bytes(&bytes).unwrap();
        assert_eq!(t.hash(), t2.hash());
    }
}
