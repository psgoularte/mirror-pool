//! Host-side correctness test for on-chain verification: a real arkworks proof,
//! converted to the on-chain byte layout, verifies through the program's
//! `groth16-solana` wrapper — and tampering is rejected. Runs on the host (the
//! `alt_bn128` operations have a native implementation), so it needs no SBF
//! build and gates the correctness claim independently of the CU benchmark.

mod common;

use common::membership_fixture;
use mirror_pool_program::verifier::{verify_membership, ParsedVerifyingKey};

#[test]
fn real_proof_verifies() {
    let fx = membership_fixture();
    let vk = ParsedVerifyingKey::parse(&fx.vk_bytes).expect("vk parses");
    verify_membership(&vk, &fx.proof, &fx.public_inputs).expect("valid proof must verify");
}

#[test]
fn tampered_public_input_rejected() {
    let mut fx = membership_fixture();
    let vk = ParsedVerifyingKey::parse(&fx.vk_bytes).expect("vk parses");
    fx.public_inputs[0][31] ^= 0x01; // corrupt the merkle_root input
    assert!(
        verify_membership(&vk, &fx.proof, &fx.public_inputs).is_err(),
        "verification must fail for a tampered public input"
    );
}

#[test]
fn tampered_proof_rejected() {
    let mut fx = membership_fixture();
    let vk = ParsedVerifyingKey::parse(&fx.vk_bytes).expect("vk parses");
    fx.proof[0] ^= 0x01; // corrupt proof_a
                         // A corrupt point may fail either at construction or at the pairing; both
                         // are errors, never a false accept.
    assert!(verify_membership(&vk, &fx.proof, &fx.public_inputs).is_err());
}

#[test]
fn malformed_vk_rejected() {
    let fx = membership_fixture();
    assert!(ParsedVerifyingKey::parse(&fx.vk_bytes[..fx.vk_bytes.len() - 1]).is_err());
    assert!(ParsedVerifyingKey::parse(&[]).is_err());
}
