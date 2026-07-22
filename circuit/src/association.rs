//! Association sets — Privacy-Pools-style compliance (Buterin, Illum, Nadler,
//! Schär & Soleimani, *Blockchain Privacy and Regulatory Compliance: Towards a
//! Practical Equilibrium*, 2023).
//!
//! An **association set** is a curated set of deposit commitments with clean
//! provenance (published by an Association Set Provider, ASP). Two proofs let an
//! honest member demonstrate compliance in zero knowledge, without revealing
//! *which* member they are:
//!
//! * **Inclusion** — "my deposit is in this good set." Implemented here as a
//!   **real ZK proof** by reusing the membership circuit against the association
//!   set's Merkle root (no new circuit): a valid proof against `set_root` proves
//!   knowledge of a secret whose commitment is a leaf of that set. Binding it to
//!   an action is done exactly as on-chain elsewhere — the inclusion proof and
//!   the pool-membership proof share the same `nullifier_hash = Poseidon(secret,
//!   epoch)`, so a matching nullifier proves the *same* commitment is in both
//!   trees.
//! * **Exclusion** — "my deposit is not in this sanctioned set." True ZK
//!   non-membership needs a dedicated sorted-tree/adjacency circuit; that is
//!   **future work** and is documented as such. This module provides the
//!   **off-chain reference** (a sorted-set adjacency witness verified natively)
//!   so the ASP can attest exclusion; it is NOT a zero-knowledge on-chain proof.
//!
//! This is the precondition that makes the anonymity metric meaningful:
//! effective-k is reported over the **associated** set, and the gap to
//! effective-k over all deposits is the Sybil exposure (see the `anonymity`
//! crate and `ARCHITECTURE.md`).
//!
//! **Exact guarantee.** These proofs attest association-set *membership*
//! (inclusion) or *non-membership* (exclusion) only — nothing about the member's
//! identity, balance, or behavior. No overclaim.

use crate::error::{CircuitError, Result};
use crate::prover::{build_witness, prove, verify, PublicInputs};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon::commitment;
use mirror_pool_common::{fr_to_bytes_be, Bytes32, TREE_DEPTH};
use rand::{CryptoRng, RngCore};

/// A curated association set: a Merkle tree of approved deposit commitments.
/// Shares the pool's tree parameters, so the membership circuit verifies against
/// its root unchanged.
pub struct AssociationSet {
    tree: MerkleTree,
}

impl Default for AssociationSet {
    fn default() -> Self {
        Self::new()
    }
}

impl AssociationSet {
    /// An empty association set at the protocol tree depth.
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(TREE_DEPTH),
        }
    }

    /// Add an approved member's commitment. Returns its leaf index.
    pub fn approve(&mut self, secret: Fr) -> Result<usize> {
        self.tree
            .insert(commitment(secret))
            .map_err(CircuitError::Witness)
    }

    /// Add an already-computed commitment (e.g. from a public deposit list).
    pub fn approve_commitment(&mut self, commitment: Fr) -> Result<usize> {
        self.tree.insert(commitment).map_err(CircuitError::Witness)
    }

    /// The set's Merkle root (its on-chain identifier).
    pub fn root(&self) -> Bytes32 {
        fr_to_bytes_be(&self.tree.root())
    }

    fn index_of(&self, secret: Fr) -> Option<usize> {
        let target = commitment(secret);
        let root = self.tree.root();
        (0..self.tree.len()).find(|&i| {
            self.tree
                .proof(i)
                .ok()
                .and_then(|p| mirror_pool_common::merkle::root_from_proof(target, &p).ok())
                == Some(root)
        })
    }
}

/// An exclusion adjacency witness: the sorted-set neighbors bracketing a
/// commitment (`None` at an end of the set).
pub type ExclusionWitness = (Option<[u8; 32]>, Option<[u8; 32]>);

/// A ZK inclusion proof: the member knows a secret whose commitment is in the
/// association set, bound to `epoch` via the shared nullifier hash.
pub struct InclusionProof {
    /// The Groth16 proof.
    pub proof: Proof<Bn254>,
    /// Its public inputs (`merkle_root` = the association-set root).
    pub public_inputs: PublicInputs,
}

/// The action binding used for a standalone inclusion proof (domain-separated
/// constant — inclusion authorizes no on-chain action by itself).
fn inclusion_binding() -> Fr {
    // A fixed, non-action selector value; distinct from any real action binding.
    Fr::from(u64::from_le_bytes(*b"ASSOCIn0"))
}

/// Prove, in zero knowledge, that `secret`'s commitment is in `set`, bound to
/// `epoch`. The resulting `public_inputs.nullifier_hash` equals the member's
/// action nullifier for the same epoch, binding the two proofs to one commitment.
pub fn prove_inclusion<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    set: &AssociationSet,
    secret: Fr,
    epoch: Fr,
    rng: &mut R,
) -> Result<InclusionProof> {
    let idx = set.index_of(secret).ok_or_else(|| {
        CircuitError::Prove("secret's commitment is not in the association set".into())
    })?;
    let path = set.tree.proof(idx).map_err(CircuitError::Witness)?;
    let assignment = build_witness(secret, &path, epoch, inclusion_binding())?;
    // The witness-derived root must be the association-set root.
    debug_assert_eq!(
        fr_to_bytes_be(&assignment.public_inputs.merkle_root),
        set.root()
    );
    let proof = prove(pk, assignment.circuit, rng)?;
    Ok(InclusionProof {
        proof,
        public_inputs: assignment.public_inputs,
    })
}

/// Verify a ZK inclusion proof against a claimed association-set root.
/// Rejects if the proof's root is not the claimed set root, or if the proof
/// itself is invalid.
pub fn verify_inclusion(
    vk: &VerifyingKey<Bn254>,
    set_root: &Bytes32,
    inclusion: &InclusionProof,
) -> Result<bool> {
    if fr_to_bytes_be(&inclusion.public_inputs.merkle_root) != *set_root {
        return Ok(false);
    }
    verify(vk, &inclusion.public_inputs, &inclusion.proof)
}

// --------------------------------------------------------------------------
// Exclusion (off-chain reference; on-chain ZK non-membership is future work).
// --------------------------------------------------------------------------

/// A sanctioned set kept **sorted** so non-membership can be shown by an
/// adjacency witness (`left < c < right` with `left`, `right` adjacent members).
pub struct SanctionedSet {
    sorted: Vec<[u8; 32]>,
}

impl SanctionedSet {
    /// Build from a set of sanctioned commitments (deduplicated + sorted).
    pub fn from_commitments(mut commitments: Vec<[u8; 32]>) -> Self {
        commitments.sort_unstable();
        commitments.dedup();
        Self {
            sorted: commitments,
        }
    }

    /// Whether `c` is in the sanctioned set.
    pub fn contains(&self, c: &[u8; 32]) -> bool {
        self.sorted.binary_search(c).is_ok()
    }

    /// Native non-membership check: returns the adjacency witness `(left, right)`
    /// bracketing `c` if `c` is **not** sanctioned, else `None`.
    ///
    /// This is the off-chain reference an ASP uses to attest exclusion. It is
    /// NOT zero-knowledge — the ZK on-chain version (a sorted-tree adjacency
    /// circuit) is documented as future work in `ARCHITECTURE.md`/`SECURITY.md`.
    pub fn exclusion_witness(&self, c: &[u8; 32]) -> Option<ExclusionWitness> {
        match self.sorted.binary_search(c) {
            Ok(_) => None, // sanctioned → cannot prove exclusion
            Err(pos) => {
                let left = if pos == 0 {
                    None
                } else {
                    Some(self.sorted[pos - 1])
                };
                let right = self.sorted.get(pos).copied();
                Some((left, right))
            }
        }
    }
}

/// Verify a native exclusion witness: `c` lies strictly between adjacent members
/// (or beyond an end), so it is not in the sanctioned set. Reference verifier
/// for the off-chain ASP flow.
pub fn verify_exclusion_witness(c: &[u8; 32], witness: &ExclusionWitness) -> bool {
    let (left, right) = witness;
    let above_left = left.map(|l| &l < c).unwrap_or(true);
    let below_right = right.map(|r| c < &r).unwrap_or(true);
    above_left && below_right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::dev_setup;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn included_member_proves_inclusion_others_cannot() {
        let (pk, vk) = dev_setup().unwrap();
        let mut set = AssociationSet::new();
        let members: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        for m in &members {
            set.approve(*m).unwrap();
        }
        let root = set.root();
        let mut rng = StdRng::seed_from_u64(1);

        // An approved member proves inclusion.
        let incl = prove_inclusion(&pk, &set, members[2], Fr::from(7u64), &mut rng).unwrap();
        assert!(verify_inclusion(&vk, &root, &incl).unwrap());

        // A non-member cannot: their commitment is not in the set, so
        // prove_inclusion refuses to build a witness.
        let outsider = Fr::from(9999u64);
        assert!(prove_inclusion(&pk, &set, outsider, Fr::from(7u64), &mut rng).is_err());
    }

    #[test]
    fn inclusion_proof_rejected_against_wrong_root() {
        let (pk, vk) = dev_setup().unwrap();
        let mut set = AssociationSet::new();
        set.approve(Fr::from(1u64)).unwrap();
        set.approve(Fr::from(2u64)).unwrap();
        let mut rng = StdRng::seed_from_u64(2);
        let incl = prove_inclusion(&pk, &set, Fr::from(1u64), Fr::from(3u64), &mut rng).unwrap();
        // Verifying against a different root must fail.
        let wrong_root = [0xEE; 32];
        assert!(!verify_inclusion(&vk, &wrong_root, &incl).unwrap());
    }

    #[test]
    fn exclusion_witness_reference() {
        let sanctioned = SanctionedSet::from_commitments(vec![[1u8; 32], [3u8; 32], [5u8; 32]]);
        // [2;32] is between [1;32] and [3;32] → excluded.
        let clean = [2u8; 32];
        let w = sanctioned.exclusion_witness(&clean).unwrap();
        assert!(verify_exclusion_witness(&clean, &w));
        // A sanctioned commitment yields no witness.
        assert!(sanctioned.exclusion_witness(&[3u8; 32]).is_none());
        assert!(sanctioned.contains(&[3u8; 32]));
    }
}
