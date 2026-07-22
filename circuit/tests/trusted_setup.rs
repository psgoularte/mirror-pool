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
//! Regenerate the committed ceremony with:
//! `cargo run -p mirror-pool-cli -- setup --out-dir setup --contributions 3`
//! (then move `transcript.bin` under `setup/transcript/`, drop `proving_key.bin`,
//! and update `PINNED_TRANSCRIPT_HASH` below to the printed hash).

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
    0x96, 0xcb, 0x28, 0x10, 0xb2, 0xc3, 0xab, 0xd2, 0x40, 0x3a, 0x63, 0xfb, 0x74, 0xbe, 0x17, 0x78,
    0xc7, 0xbf, 0x05, 0x17, 0x22, 0x8f, 0x6e, 0xe4, 0xb9, 0xc0, 0x32, 0x22, 0x1c, 0x13, 0xf6, 0xe6,
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
}
