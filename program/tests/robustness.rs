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
    assert!(Instruction::unpack(&[]).is_err(), "empty data");
    assert!(
        Instruction::unpack(&[3, 0, 0]).is_err(),
        "truncated ExecuteAction"
    );
    assert!(
        Instruction::unpack(&[1]).is_err(),
        "InitializePool missing depth+vk"
    );
    assert!(
        Instruction::unpack(&[2, 0, 0]).is_err(),
        "Deposit truncated commitment"
    );
    assert!(Instruction::unpack(&[99]).is_err(), "unknown tag");
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
    // A borsh ExecuteAction with a proof that is one byte short must fail to
    // decode rather than silently misparse.
    let mut data = vec![3u8];
    data.extend_from_slice(&[0u8; 255]); // proof is 256 bytes; supply 255
    data.extend_from_slice(&[0u8; 128]); // public inputs
    data.push(0); // selector
    data.extend_from_slice(&0u32.to_le_bytes()); // empty params
    assert!(Instruction::unpack(&data).is_err());
}
