//! Groth16 setup / prove / verify over the membership circuit, plus the
//! canonical public-input encoding shared with the on-chain verifier.

use crate::circuit::MembershipCircuit;
use crate::error::{CircuitError, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use mirror_pool_common::field::{fr_from_bytes_be, fr_to_bytes_be, Bytes32};
use mirror_pool_common::merkle::{root_from_proof, MerkleProof};
use mirror_pool_common::poseidon;
use rand::{CryptoRng, RngCore};

/// The circuit's public inputs, in the canonical wire order the circuit
/// allocates them and the on-chain verifier consumes them.
///
/// **Order is load-bearing**: `[merkle_root, nullifier_hash, epoch_id,
/// action_binding]`. It must match `MembershipCircuit::generate_constraints`
/// and the on-chain verifier (milestone 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub merkle_root: Fr,
    pub nullifier_hash: Fr,
    pub epoch_id: Fr,
    pub action_binding: Fr,
}

impl PublicInputs {
    /// Field vector in canonical order, as `ark-groth16` verification expects.
    pub fn to_field_vec(&self) -> Vec<Fr> {
        vec![
            self.merkle_root,
            self.nullifier_hash,
            self.epoch_id,
            self.action_binding,
        ]
    }

    /// Big-endian 32-byte encoding of each input, in canonical order — the
    /// layout the on-chain program reads from instruction data.
    pub fn to_bytes(&self) -> Vec<Bytes32> {
        self.to_field_vec().iter().map(fr_to_bytes_be).collect()
    }

    /// Decode from four big-endian 32-byte limbs in canonical order.
    pub fn from_bytes(limbs: &[Bytes32; 4]) -> Result<Self> {
        let decode = |b: &Bytes32| fr_from_bytes_be(b).map_err(CircuitError::Witness);
        Ok(Self {
            merkle_root: decode(&limbs[0])?,
            nullifier_hash: decode(&limbs[1])?,
            epoch_id: decode(&limbs[2])?,
            action_binding: decode(&limbs[3])?,
        })
    }
}

/// A ready-to-prove assignment: the circuit plus the public inputs it commits
/// to. Built by [`build_witness`] so the two can never drift.
pub struct Assignment {
    pub circuit: MembershipCircuit,
    pub public_inputs: PublicInputs,
}

/// Construct a consistent witness from a member's secret, their Merkle
/// authentication path, the epoch, and the action binding.
///
/// The Merkle root and nullifier hash are **computed here** from the secret and
/// path (never taken on faith), so a caller cannot accidentally prove against a
/// mismatched public input.
pub fn build_witness(
    secret: Fr,
    proof: &MerkleProof,
    epoch_id: Fr,
    action_binding: Fr,
) -> Result<Assignment> {
    let commitment = poseidon::commitment(secret);
    let merkle_root = root_from_proof(commitment, proof)?;
    let nullifier_hash = poseidon::nullifier_hash(secret, epoch_id);

    let depth = proof.path_elements.len();
    let circuit = MembershipCircuit {
        depth,
        secret: Some(secret),
        path_elements: proof.path_elements.iter().copied().map(Some).collect(),
        path_indices: proof.path_indices.iter().copied().map(Some).collect(),
        merkle_root: Some(merkle_root),
        nullifier_hash: Some(nullifier_hash),
        epoch_id: Some(epoch_id),
        action_binding: Some(action_binding),
    };
    Ok(Assignment {
        circuit,
        public_inputs: PublicInputs {
            merkle_root,
            nullifier_hash,
            epoch_id,
            action_binding,
        },
    })
}

/// Run the (per-circuit) Groth16 trusted setup for a tree of the given depth.
///
/// This uses a caller-supplied RNG. For production the proving/verifying keys
/// must come from a proper multi-party ceremony; this function is the local
/// equivalent used by tests and the dev CLI. The security of the setup rests on
/// the randomness (toxic waste) being discarded — documented for operators.
pub fn setup<R: RngCore + CryptoRng>(
    depth: usize,
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    Groth16::<Bn254>::circuit_specific_setup(MembershipCircuit::empty(depth), rng)
        .map_err(|e| CircuitError::Setup(e.to_string()))
}

/// Generate a proof for a fully-assigned circuit.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circuit: MembershipCircuit,
    rng: &mut R,
) -> Result<Proof<Bn254>> {
    Groth16::<Bn254>::prove(pk, circuit, rng).map_err(|e| CircuitError::Prove(e.to_string()))
}

/// Verify a proof against public inputs using an unprepared verifying key.
pub fn verify(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &PublicInputs,
    proof: &Proof<Bn254>,
) -> Result<bool> {
    let pvk = Groth16::<Bn254>::process_vk(vk).map_err(|e| CircuitError::Verify(e.to_string()))?;
    verify_prepared(&pvk, public_inputs, proof)
}

/// Verify against a prepared verifying key (cheaper when verifying many proofs).
pub fn verify_prepared(
    pvk: &PreparedVerifyingKey<Bn254>,
    public_inputs: &PublicInputs,
    proof: &Proof<Bn254>,
) -> Result<bool> {
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs.to_field_vec(), proof)
        .map_err(|e| CircuitError::Verify(e.to_string()))
}

/// Serialize an arkworks value (key or proof) to compressed bytes.
pub fn serialize_compressed<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|e| CircuitError::Serialize(e.to_string()))?;
    Ok(buf)
}

/// Deserialize an arkworks value from compressed bytes.
pub fn deserialize_compressed<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    T::deserialize_compressed(bytes).map_err(|e| CircuitError::Serialize(e.to_string()))
}
