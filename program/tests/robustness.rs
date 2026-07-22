//! Robustness / abuse-resistance (VALIDATION Level 5): malformed inputs must
//! produce typed errors, never a panic (a panic is a DoS vector) and never a
//! false `Ok`. Instruction and verifying-key decoding are the untrusted entry
//! points reachable before any signature or account check.

use ark_std::rand::rngs::StdRng;
use ark_std::rand::{RngCore, SeedableRng};
use mirror_pool_program::instruction::Instruction;
use mirror_pool_program::verifier::ParsedVerifyingKey;

#[test]
fn instruction_unpack_never_panics_on_garbage() {
    let mut rng = StdRng::seed_from_u64(0xF0F0);
    for _ in 0..5000 {
        let len = (rng.next_u32() % 600) as usize;
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        // Must return Ok or Err — never panic, never abort.
        let _ = Instruction::unpack(&bytes);
    }
    // Explicit truncations of a known tag are errors, not panics.
    // Tags: 0=Init, 1=Deposit, 2=ExecuteAction, 3=NoOp, 4=Open, 5=Close,
    // 6=SetScreening, 7=Register (8=VerifyMembership only with `bench`).
    assert!(Instruction::unpack(&[]).is_err(), "empty data");
    assert!(
        Instruction::unpack(&[0]).is_err(),
        "InitializePool missing depth+vk"
    );
    assert!(
        Instruction::unpack(&[1, 0, 0]).is_err(),
        "Deposit truncated commitment"
    );
    assert!(
        Instruction::unpack(&[2, 0, 0]).is_err(),
        "truncated ExecuteAction"
    );
    assert!(Instruction::unpack(&[99]).is_err(), "unknown tag");
}

/// SECURITY (1b): the benchmark-only `VerifyMembership` (tag 8) must NOT be a
/// valid instruction in the default (deployed) build.
#[cfg(not(feature = "bench"))]
#[test]
fn verify_membership_absent_from_default_build() {
    let mut data = vec![8u8];
    data.extend_from_slice(&[0u8; 384]); // proof + public inputs payload
    assert!(
        Instruction::unpack(&data).is_err(),
        "VerifyMembership must not decode without the bench feature"
    );
}

#[test]
fn verifying_key_parse_never_panics_on_garbage() {
    let mut rng = StdRng::seed_from_u64(0x0FF0);
    for _ in 0..5000 {
        let len = (rng.next_u32() % 900) as usize;
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        let _ = ParsedVerifyingKey::parse(&bytes);
    }
    assert!(ParsedVerifyingKey::parse(&[]).is_err());
    assert!(ParsedVerifyingKey::parse(&[0u8; 100]).is_err(), "too short");
    // Correct header length but a wrong IC count must be rejected, not read OOB.
    assert!(
        ParsedVerifyingKey::parse(&[0u8; 448 + 1]).is_err(),
        "ic_len 0 != 5"
    );
}

#[test]
fn wrong_length_execute_action_is_rejected() {
    // A borsh ExecuteAction (tag 2) with a proof one byte short must fail to
    // decode rather than silently misparse.
    let mut data = vec![2u8];
    data.extend_from_slice(&[0u8; 255]); // proof is 256 bytes; supply 255
    data.extend_from_slice(&[0u8; 128]); // public inputs
    data.push(0); // selector
    data.extend_from_slice(&0u32.to_le_bytes()); // empty params
    assert!(Instruction::unpack(&data).is_err());
}
