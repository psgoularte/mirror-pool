#!/usr/bin/env bash
#
# mirror-pool demo — runs the entire protocol end-to-end with real cryptography.
#
# It uses litesvm as an in-process local validator (via the workspace-excluded
# `bench` crate), so the full flow runs against the ACTUAL compiled SBF bytecode
# with genuine Groth16 proofs — no external validator, no devnet, fully
# reproducible.
#
# Requirements: a Rust toolchain and the Solana/Agave CLI providing
# `cargo build-sbf` (see README).
#
# Usage: ./demo.sh
set -euo pipefail

cd "$(dirname "$0")"

echo "==> 1/6  Building the DEPLOYED program artifact (default features — the"
echo "         benchmark-only VerifyMembership instruction is NOT included)"
# --arch v3 matches the sBPF version enabled on current Agave clusters (the
# default v0 is not yet feature-gated on-chain and fails `program deploy`).
cargo build-sbf --manifest-path program/Cargo.toml --arch v3

echo
echo "==> 2/6  Full flow: initialize -> deposit -> open epoch -> prove ->"
echo "         execute_action (no-op via PDA + denominated SOL transfer);"
echo "         enforces min-k, denominations, pool-scoped nullifiers, + negatives"
cargo run --release --manifest-path bench/Cargo.toml --bin flow

echo
echo "==> 3/6  Compliance: deposit-screening hook + viewing-key disclosure"
cargo run --release --manifest-path bench/Cargo.toml --bin compliance

echo
echo "==> 4/6  Privacy red-team: attack the public trace (fee payer, linkage,"
echo "         anonymity set) — the headline privacy metric"
cargo run --release --manifest-path bench/Cargo.toml --bin trace

echo
echo "==> 5/6  Compute-unit benchmark (real proof verified on-chain, < 200k CU)."
echo "         Uses a SEPARATE bench-featured build; the deployed .so above stays"
echo "         benchmark-free. The default artifact is restored afterwards."
cargo build-sbf --manifest-path program/Cargo.toml --features bench --arch v3
cargo test -p mirror-pool-program --features bench --test gen_fixture -- --ignored --nocapture >/dev/null
cargo run --release --manifest-path bench/Cargo.toml --bin cu-bench
cargo build-sbf --manifest-path program/Cargo.toml --arch v3  # restore the deployed artifact

echo
echo "==> 6/6  CLI: keys, and the anonymity-set simulation"
cargo build -q -p mirror-pool-cli
BIN=target/debug/mirror-pool
echo "--- keygen (member) ---";  "$BIN" keygen
echo "--- sim ---";              "$BIN" sim --members 64 --actors 12 --epochs 3

echo
echo "==> demo complete. See ARCHITECTURE.md for the threat model and SECURITY.md"
echo "    for the trusted-setup ceremony path and review findings."
