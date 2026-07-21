//! End-to-end circuit tests: a real Groth16 setup, real proofs, real
//! verification. Covers the happy path and the mandatory negative cases
//! (SPEC §4.1, §7): wrong secret, tampered path, action-binding mismatch, and
//! wrong epoch. No mocked cryptography anywhere.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use mirror_pool_circuit::circuit::MembershipCircuit;
use mirror_pool_circuit::prover::{build_witness, prove, setup, verify, Assignment, PublicInputs};
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon;
use mirror_pool_common::TREE_DEPTH;

/// Build a small populated tree and return it plus the members' secrets.
fn populated_tree(n: u64) -> (MerkleTree, Vec<Fr>) {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut secrets = Vec::new();
    for _ in 0..n {
        let secret = Fr::rand(&mut rng);
        tree.insert(poseidon::commitment(secret)).unwrap();
        secrets.push(secret);
    }
    (tree, secrets)
}

#[test]
fn valid_proof_verifies() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).unwrap();

    let (tree, secrets) = populated_tree(8);
    let member = 3usize;
    let proof_path = tree.proof(member).unwrap();
    let epoch = Fr::from(42u64);
    let action = Fr::from(0xABCDu64);

    let Assignment {
        circuit,
        public_inputs,
    } = build_witness(secrets[member], &proof_path, epoch, action).unwrap();

    // The witness-derived root matches the tree's actual root.
    assert_eq!(public_inputs.merkle_root, tree.root());

    let proof = prove(&pk, circuit, &mut rng).unwrap();
    assert!(verify(&vk, &public_inputs, &proof).unwrap());
}

#[test]
fn wrong_secret_fails() {
    // A prover who does not know a secret in the tree cannot produce a proof
    // whose (honestly recomputed) root matches the real tree root.
    let mut rng = StdRng::seed_from_u64(2);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).unwrap();

    let (tree, _secrets) = populated_tree(8);
    let proof_path = tree.proof(2).unwrap();
    let epoch = Fr::from(7u64);
    let action = Fr::from(1u64);

    // Attacker uses a secret not in the tree with a member's path.
    let bogus_secret = Fr::from(999_999u64);
    let Assignment {
        circuit,
        public_inputs,
    } = build_witness(bogus_secret, &proof_path, epoch, action).unwrap();

    // The proof is internally consistent, but its root is NOT the tree's root,
    // so verification against the real tree root must fail.
    assert_ne!(public_inputs.merkle_root, tree.root());
    let proof = prove(&pk, circuit, &mut rng).unwrap();

    let claim_against_real_root = PublicInputs {
        merkle_root: tree.root(),
        ..public_inputs.clone()
    };
    assert!(!verify(&vk, &claim_against_real_root, &proof).unwrap());
}

#[test]
fn tampered_path_makes_constraints_unsatisfiable() {
    // Flipping a path element makes the recomputed root disagree with the
    // public root, so the Merkle-inclusion constraint cannot be satisfied and
    // no valid proof exists. We assert this at the R1CS level (the Groth16
    // prover asserts satisfiability internally, so a satisfiable system is a
    // precondition for proving at all).
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    let (tree, secrets) = populated_tree(8);
    let member = 5usize;
    let mut proof_path = tree.proof(member).unwrap();
    proof_path.path_elements[0] += Fr::from(1u64); // tamper

    let epoch = Fr::from(9u64);
    let action = Fr::from(2u64);

    // Pin the public root to the real tree root while the witness path is
    // tampered.
    let mut circuit = build_witness(secrets[member], &proof_path, epoch, action)
        .unwrap()
        .circuit;
    circuit.merkle_root = Some(tree.root());

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "tampered path must leave the constraint system unsatisfiable"
    );
}

#[test]
fn honest_witness_is_satisfiable() {
    // Positive control for the test above: the untampered witness satisfies the
    // full constraint system.
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    let (tree, secrets) = populated_tree(8);
    let proof_path = tree.proof(5).unwrap();
    let circuit = build_witness(secrets[5], &proof_path, Fr::from(9u64), Fr::from(2u64))
        .unwrap()
        .circuit;
    let _ = tree; // root already folded into the witness

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn action_binding_mismatch_fails() {
    // A proof is bound to its action_binding: verifying it against a different
    // action binding must fail. This is the anti-replay guarantee.
    let mut rng = StdRng::seed_from_u64(4);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).unwrap();

    let (tree, secrets) = populated_tree(8);
    let proof_path = tree.proof(1).unwrap();
    let epoch = Fr::from(11u64);
    let action = Fr::from(0x1111u64);

    let Assignment {
        circuit,
        public_inputs,
    } = build_witness(secrets[1], &proof_path, epoch, action).unwrap();
    let proof = prove(&pk, circuit, &mut rng).unwrap();

    assert!(verify(&vk, &public_inputs, &proof).unwrap());
    let replayed = PublicInputs {
        action_binding: Fr::from(0x2222u64),
        ..public_inputs
    };
    assert!(
        !verify(&vk, &replayed, &proof).unwrap(),
        "proof must not verify for a different action binding"
    );
}

#[test]
fn wrong_epoch_fails() {
    // The nullifier hash is epoch-scoped. Verifying a proof under a different
    // epoch_id (with the nullifier that matches the original epoch) must fail.
    let mut rng = StdRng::seed_from_u64(5);
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).unwrap();

    let (tree, secrets) = populated_tree(8);
    let proof_path = tree.proof(4).unwrap();
    let action = Fr::from(3u64);
    let epoch = Fr::from(100u64);

    let Assignment {
        circuit,
        public_inputs,
    } = build_witness(secrets[4], &proof_path, epoch, action).unwrap();
    let proof = prove(&pk, circuit, &mut rng).unwrap();
    assert!(verify(&vk, &public_inputs, &proof).unwrap());

    let wrong_epoch = PublicInputs {
        epoch_id: Fr::from(101u64),
        ..public_inputs
    };
    assert!(!verify(&vk, &wrong_epoch, &proof).unwrap());
}

#[test]
fn public_input_bytes_roundtrip() {
    let pi = PublicInputs {
        merkle_root: Fr::from(1u64),
        nullifier_hash: Fr::from(2u64),
        epoch_id: Fr::from(3u64),
        action_binding: Fr::from(4u64),
    };
    let bytes = pi.to_bytes();
    let arr: [_; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    assert_eq!(PublicInputs::from_bytes(&arr).unwrap(), pi);
}

#[test]
fn empty_circuit_has_expected_shape() {
    let c = MembershipCircuit::empty(TREE_DEPTH);
    assert_eq!(c.path_elements.len(), TREE_DEPTH);
    assert_eq!(c.path_indices.len(), TREE_DEPTH);
    assert!(c.secret.is_none());
}
