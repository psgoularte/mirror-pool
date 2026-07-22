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

echo "==> 1/5  Building the on-chain program (SBF bytecode)"
cargo build-sbf --manifest-path program/Cargo.toml

echo
echo "==> 2/5  Compute-unit benchmark (real proof verified on-chain, < 200k CU)"
cargo test -p mirror-pool-program --test gen_fixture -- --ignored --nocapture >/dev/null
cargo run --release --manifest-path bench/Cargo.toml --bin cu-bench

echo
echo "==> 3/5  Full flow: initialize -> deposit -> open epoch -> prove ->"
echo "         execute_action (no-op via PDA + real SOL transfer) -> negatives"
cargo run --release --manifest-path bench/Cargo.toml --bin flow

echo
echo "==> 4/5  Compliance: deposit-screening hook + viewing-key disclosure"
cargo run --release --manifest-path bench/Cargo.toml --bin compliance

echo
echo "==> 5/5  CLI: keys, and the anonymity-set simulation"
cargo build -q -p mirror-pool-cli
BIN=target/debug/mirror-pool
echo "--- keygen (member) ---";  "$BIN" keygen
echo "--- sim ---";              "$BIN" sim --members 64 --actors 12 --epochs 3

echo
echo "==> demo complete. See ARCHITECTURE.md for the threat model and the"
echo "    on-chain deploy path (cargo build-sbf + solana program deploy)."
