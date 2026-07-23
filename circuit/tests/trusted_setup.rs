//! Trusted-setup verification (Final pass, Part 1).
//!
//! The committed key was produced by a **multi-contributor Phase-2 ceremony**
//! (`circuit::ceremony`), NOT a reproducible single-party seed. So we do not
//! regenerate-and-diff; instead we:
//!
//! 1. verify the full contribution chain in the committed transcript,
//! 2. pin the transcript by its SHA-256 hash (so it can't be swapped), and
//! 3. confirm the committed on-chain verifying key is exactly the ceremony's
//!    output.
//!
//! Regenerate the committed ceremony with the distributable flow (each step can
//! run on a different machine / operator):
//! ```text
//! cli ceremony-init --out-dir ceremony
//! cli ceremony-contribute --params ceremony/params.bin \
//!     --transcript ceremony/transcript.bin --contributor <label> --out-dir ceremony
//! # …repeat ceremony-contribute for each INDEPENDENT operator…
//! cli ceremony-finalize --params ceremony/params.bin \
//!     --transcript ceremony/transcript.bin --out-dir setup
//! ```
//! then update `PINNED_TRANSCRIPT_HASH` below to the printed hash. Anyone can
//! re-check the committed result with `cli verify-setup`.

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use mirror_pool_circuit::ceremony::{verify_transcript, Transcript};
use mirror_pool_circuit::solana::vk_to_solana;

const VK_ARK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../setup/verifying_key.bin"
));
const VK_SOLANA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../setup/verifying_key.solana.bin"
));
const TRANSCRIPT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../setup/transcript/transcript.bin"
));

/// SHA-256 of the committed transcript (printed by `cli setup`). Pinning here —
/// not in a file — is what stops the transcript from being swapped.
const PINNED_TRANSCRIPT_HASH: [u8; 32] = [
    0xd9, 0xeb, 0xc2, 0x4c, 0xff, 0x84, 0x0a, 0xc0, 0xaf, 0x8b, 0x52, 0xe6, 0x00, 0x73, 0x0f, 0x9a,
    0x65, 0x0e, 0x25, 0x44, 0x20, 0x2c, 0x33, 0x27, 0x13, 0x7e, 0x09, 0x29, 0x52, 0xaf, 0x21, 0x4e,
];

#[test]
fn committed_setup_is_a_valid_ceremony() {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(VK_ARK).expect("committed ark VK");
    let transcript = Transcript::from_bytes(TRANSCRIPT).expect("committed transcript");

    // (1) The contribution chain verifies and produces this VK's delta.
    assert!(
        verify_transcript(&transcript, &vk),
        "committed transcript does not verify against the committed VK"
    );
    // (2) The transcript is the pinned one (not swapped).
    assert_eq!(
        transcript.hash(),
        PINNED_TRANSCRIPT_HASH,
        "committed transcript hash changed — re-pin only after a deliberate re-ceremony"
    );
    // (3) The committed on-chain VK is exactly this ceremony's output.
    assert_eq!(
        vk_to_solana(&vk).to_bytes().as_slice(),
        VK_SOLANA,
        "committed on-chain VK does not match the ceremony verifying key"
    );
    // At least one real contribution (a ceremony, not a single-party setup).
    assert!(!transcript.contributions.is_empty());
    // Honest labeling: the shipped key has exactly ONE independent contributor
    // (single operator, one machine). This is the testnet-grade status stated in
    // docs/security.md — do NOT bump this without genuinely independent parties.
    assert_eq!(
        transcript.independent_contributors(),
        1,
        "shipped ceremony is single-operator; update docs + count together if that changes"
    );
}
