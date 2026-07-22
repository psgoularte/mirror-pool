//! Writes a real membership-proof fixture to disk for the compute-unit
//! benchmark in the workspace-excluded `bench/` crate.
//!
//! `bench/` cannot depend on this crate (it keeps a separate Solana version to
//! run litesvm), so the fixture crosses the boundary as a flat file of raw
//! bytes. `#[ignore]`d — run explicitly before the benchmark:
//!
//! ```sh
//! cargo test -p mirror-pool-program --features bench --test gen_fixture -- --ignored
//! ```
//!
//! Requires the `bench` feature (the fixture builds the benchmark-only
//! `VerifyMembership` instruction). Without it, this test compiles to nothing.
#![cfg(feature = "bench")]

mod common;

use common::membership_fixture;
use std::io::Write;
use std::path::PathBuf;

/// Default fixture location: `target/mirror-pool-cu-fixture.bin`.
fn fixture_path() -> PathBuf {
    if let Ok(p) = std::env::var("MIRROR_POOL_FIXTURE") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("mirror-pool-cu-fixture.bin")
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[test]
#[ignore = "fixture generator for the bench crate; run with --ignored"]
fn write_cu_fixture() {
    let fx = membership_fixture();

    // Format: [vk_len u32-le][vk][data_len u32-le][instruction_data].
    let mut buf = Vec::new();
    put(&mut buf, &fx.vk_bytes);
    put(&mut buf, &fx.instruction_data);

    let path = fixture_path();
    let mut f = std::fs::File::create(&path)
        .unwrap_or_else(|e| panic!("create fixture {}: {e}", path.display()));
    f.write_all(&buf).expect("write fixture");
    println!("wrote CU benchmark fixture to {}", path.display());
}
