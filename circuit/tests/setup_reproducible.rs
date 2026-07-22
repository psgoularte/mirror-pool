//! Trusted-setup reproducibility gate (hardening Section 2).
//!
//! The committed development verifying key (`setup/verifying_key.solana.bin`)
//! must be exactly regenerable from `dev_setup()` (a fixed-seed, single-party
//! DEV setup — NOT production-trusted; see SECURITY.md). If the circuit or the
//! setup ever drifts, this test fails.
//!
//! Regenerate the committed key with:
//! `cargo test -p mirror-pool-circuit --test setup_reproducible -- --ignored write_dev_vk`

use mirror_pool_circuit::prover::dev_setup;
use mirror_pool_circuit::solana::vk_to_solana;

const COMMITTED_VK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../setup/verifying_key.solana.bin"
));

#[test]
fn dev_vk_matches_committed() {
    let (_pk, vk) = dev_setup().expect("dev setup");
    let regenerated = vk_to_solana(&vk).to_bytes();
    assert_eq!(
        regenerated.as_slice(),
        COMMITTED_VK,
        "the committed dev VK is not reproducible from dev_setup(); \
         regenerate with the --ignored write_dev_vk test if the circuit changed"
    );
}

#[test]
#[ignore = "regenerates the committed dev VK on disk"]
fn write_dev_vk() {
    let (_pk, vk) = dev_setup().unwrap();
    let bytes = vk_to_solana(&vk).to_bytes();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../setup/verifying_key.solana.bin"
    );
    std::fs::write(path, &bytes).unwrap();
    println!("wrote {} bytes to {path}", bytes.len());
}
