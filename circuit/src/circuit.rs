//! The mirror-pool membership circuit (Groth16 over BN254).
//!
//! Proves, in zero knowledge, "I know a secret whose commitment is a leaf in
//! the tree with this root, and this nullifier hash is the epoch-scoped
//! nullifier for that secret" — without revealing which leaf.
//!
//! ## Statement
//!
//! Private (witness): `secret`, `path_elements[DEPTH]`, `path_indices[DEPTH]`.
//! Public (instance): `merkle_root`, `nullifier_hash`, `epoch_id`,
//! `action_binding`.
//!
//! ## Constraints
//!
//! 1. `commitment = Poseidon(secret)` and `commitment` is included under
//!    `merkle_root` along the given path.
//! 2. `nullifier_hash = Poseidon(secret, epoch_id)` — epoch-scoped, so one
//!    membership can act exactly once per epoch.
//! 3. `action_binding` is bound into the proof (a squaring constraint pins the
//!    public input into the R1CS so the proof cannot be replayed against a
//!    different intended action).
//!
//! The public-input **order** here — root, nullifier, epoch, action_binding —
//! is the canonical wire order the on-chain verifier (milestone 3) and
//! [`crate::prover::PublicInputs`] rely on. Do not reorder.

use crate::poseidon_gadget::{hash_gadget, hash_pair_gadget};
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Full assignment (public + private) that instantiates the circuit for
/// proving. For key generation, use [`MembershipCircuit::empty`], which carries
/// only the shape (tree depth) with no secret data.
#[derive(Clone)]
pub struct MembershipCircuit {
    /// Tree depth (circuit shape). Public/structural, not a witness value.
    pub depth: usize,
    /// Private: the member's secret (nullifier preimage).
    pub secret: Option<Fr>,
    /// Private: sibling hashes along the authentication path.
    pub path_elements: Vec<Option<Fr>>,
    /// Private: direction bits along the authentication path.
    pub path_indices: Vec<Option<bool>>,
    /// Public: the Merkle root membership is proved under.
    pub merkle_root: Option<Fr>,
    /// Public: `Poseidon(secret, epoch_id)`.
    pub nullifier_hash: Option<Fr>,
    /// Public: the epoch this proof is valid for.
    pub epoch_id: Option<Fr>,
    /// Public: the action/params this proof authorizes.
    pub action_binding: Option<Fr>,
}

impl MembershipCircuit {
    /// A witness-free instance of the right shape, for Groth16 setup.
    pub fn empty(depth: usize) -> Self {
        Self {
            depth,
            secret: None,
            path_elements: vec![None; depth],
            path_indices: vec![None; depth],
            merkle_root: None,
            nullifier_hash: None,
            epoch_id: None,
            action_binding: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- Public inputs, allocated in canonical order. ---
        let merkle_root = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let epoch_id = FpVar::new_input(cs.clone(), || {
            self.epoch_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let action_binding = FpVar::new_input(cs.clone(), || {
            self.action_binding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // --- Private witness. ---
        let secret = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        if self.path_elements.len() != self.depth || self.path_indices.len() != self.depth {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut path_elements = Vec::with_capacity(self.depth);
        for e in &self.path_elements {
            path_elements.push(FpVar::new_witness(cs.clone(), || {
                e.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        let mut path_indices = Vec::with_capacity(self.depth);
        for b in &self.path_indices {
            path_indices.push(Boolean::new_witness(cs.clone(), || {
                b.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // --- (1) commitment = Poseidon(secret), then Merkle inclusion. ---
        let commitment = hash_gadget(std::slice::from_ref(&secret))?;

        let mut cur = commitment;
        for (sibling, is_right) in path_elements.iter().zip(path_indices.iter()) {
            // If the current node is the right child (bit = 1), the parent is
            // Poseidon(sibling, current); otherwise Poseidon(current, sibling).
            let left = is_right.select(sibling, &cur)?;
            let right = is_right.select(&cur, sibling)?;
            cur = hash_pair_gadget(&left, &right)?;
        }
        cur.enforce_equal(&merkle_root)?;

        // --- (2) nullifier_hash = Poseidon(secret, epoch_id). ---
        let computed_nullifier = hash_gadget(&[secret, epoch_id])?;
        computed_nullifier.enforce_equal(&nullifier_hash)?;

        // --- (3) Bind action_binding into the proof. ---
        // A Groth16 public input is part of the verification equation only if it
        // appears in at least one constraint; an unreferenced input could be
        // dropped by the constraint optimizer, letting a proof be replayed for a
        // different action. Squaring it registers a multiplicative constraint
        // that references the input, pinning it into the R1CS. The squared value
        // itself is unused — the reference is the whole point.
        let _ab_pinned = action_binding.square()?;

        Ok(())
    }
}
