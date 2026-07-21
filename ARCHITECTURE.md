# mirror-pool architecture

This document is built up milestone by milestone. It currently covers the
crypto foundation (milestone 1); the on-chain state machine, the `Action`
extension guide, the compliance design, and the full threat model are filled in
as their milestones land.

## Component overview

```
                    off-chain (Rust)                         on-chain (SBF)
  ┌──────────┐   ┌──────────┐   ┌──────────┐          ┌───────────────────────┐
  │  cli     │──▶│ circuit  │   │ relayer  │──tx────▶ │  mirror-pool program   │
  │ keygen   │   │ (prover) │   │ (pays fee│          │  • Merkle tree + roots │
  │ deposit  │   │ Groth16  │   │  batches │          │  • nullifier set       │
  │ prove    │──▶│  BN254   │──▶│  epochs) │          │  • epoch schedule      │
  │ execute  │   └────┬─────┘   └──────────┘          │  • Groth16 verify      │
  │ disclose │        │                               │  • PDA-signed CPI      │
  │ sim      │        ▼                               │  • compliance          │
  └────┬─────┘   ┌──────────┐                         └───────────┬───────────┘
       └────────▶│  common  │◀─── pinned Poseidon params ─────────┘
                 │ (shared) │      (single source of truth)
                 └──────────┘
```

Every crate depends on `common` for the field type, byte encodings, tree
dimensions, and — critically — the Poseidon parameters. Nothing else defines a
hash constant.

## Cryptographic foundation (milestone 1)

### The Poseidon consistency invariant

The protocol is sound only if three Poseidon implementations agree
byte-for-byte:

1. the arkworks R1CS **gadget** inside the ZK circuit,
2. the native **prover-side** hasher, and
3. the **on-chain** hasher (Solana's `sol_poseidon` syscall).

If any two diverge, a proof valid off-chain fails on-chain — or, worse, the
Merkle root the program computes never matches the one the circuit proved
membership under, and deposits become unspendable. The SPEC flags this as the
project's critical footgun.

**How we neutralize it.** `common` pins exactly one parameter set — the
circom-compatible BN254 `x5` constants from
[`light-poseidon`](https://github.com/Lightprotocol/light-poseidon), the same
implementation Light Protocol's `sol_poseidon` syscall runs on-chain. `common`
re-implements the circom permutation over those constants in plain Rust and a
test (`poseidon::tests::poseidon_matches_reference`) asserts, over 1000 random
inputs per arity, that it reproduces `light-poseidon`'s output exactly. The
circuit crate (milestone 2) tests its gadget against `common`. The chain of
equalities — gadget = native = `light-poseidon` = syscall — closes the loop.

A subtle reason we hand-roll rather than reuse arkworks' `PoseidonSponge`: the
arkworks sponge reads its digest from `state[capacity]`, whereas
circom / `light-poseidon` / the syscall read `state[0]`. Dropping in arkworks'
sponge would silently produce a *different* hash. `common::poseidon` follows the
circom construction (`state = [0, inputs…]`, permute, output `state[0]`).

### Field encoding

All field elements cross crate and chain boundaries as canonical **big-endian**
32-byte values (`common::field`), matching what `sol_poseidon` and
`groth16-solana` consume. The decoder rejects non-canonical encodings (values
`≥` the field modulus) rather than reducing them, closing a
second-encoding forgery vector.

### Shared dimensions

- `TREE_DEPTH = 20` → up to ~1.05M commitments; a 20-hash in-circuit path.
- `ROOT_HISTORY_SIZE = 64` → recent roots retained so a proof survives deposits
  that advance the tree between proving and landing (SPEC §7).

## Membership circuit (milestone 2)

The Groth16/BN254 circuit (`circuit`) proves, in zero knowledge, "I know a
secret whose commitment is a leaf under this root, and this is its epoch-scoped
nullifier" — without revealing which leaf.

- **Private witness:** `secret`, `path_elements[20]`, `path_indices[20]`.
- **Public instance (canonical order):** `merkle_root`, `nullifier_hash`,
  `epoch_id`, `action_binding`. This order is load-bearing — the on-chain
  verifier consumes the inputs in exactly this sequence.
- **Constraints:** (1) `commitment = Poseidon(secret)` and Merkle inclusion up
  the path; (2) `nullifier_hash = Poseidon(secret, epoch_id)`, epoch-scoped so a
  membership acts once per epoch; (3) `action_binding` pinned into the R1CS via
  a squaring constraint so a proof cannot be replayed for a different action.

The Poseidon hashing inside the circuit is the R1CS gadget in
`circuit::poseidon_gadget`, which mirrors `common::poseidon` and is tested equal
to it. `prover.rs` owns setup/prove/verify and the `PublicInputs` byte encoding
shared with the chain. The trusted setup here is a local dev/test setup; a
production deployment must source the proving/verifying keys from a multi-party
ceremony (the toxic waste must be discarded) — called out in the code.

Negative tests (mandatory per SPEC §7) cover wrong secret, tampered path,
action-binding mismatch, and wrong epoch, each with real proofs.

## On-chain verification (milestone 3)

The program verifies membership proofs with
[`groth16-solana`](https://github.com/Lightprotocol/groth16-solana) (audited
under Light Protocol v3), which runs BN254 Groth16 verification through the
`alt_bn128` syscalls. Three byte-layout quirks are handled explicitly in
`circuit::solana` (which converts arkworks keys/proofs to the on-chain layout):

1. **Endianness** — each 32-byte coordinate is big-endian (arkworks is
   little-endian internally); we emit big-endian by construction.
2. **G2 coordinate order** — the precompile encodes `Fq2` imaginary-part-first
   (`c1 || c0`), the reverse of arkworks' in-memory order.
3. **`proof_a` negation** — `A` is negated before encoding, per the verifier's
   rearranged pairing equation.

The program side (`program::verifier`) is deliberately **byte-only** — it never
links arkworks, which is what keeps it inside the compute budget on BPF.

**Correctness** is gated two ways: a host test (`program`'s `verify_host`)
converts a real arkworks proof and verifies it through the exact
`groth16-solana` code the program runs, and rejects tampered proofs / public
inputs / verifying keys. **Cost** is gated by the `bench/` crate, which runs the
actual SBF bytecode in litesvm over a real proof:

> **VerifyMembership: ~98k compute units** — comfortably under the ~200k budget.

`bench/` is workspace-excluded so it can track the latest Solana release for
litesvm without forcing the program off solana-program 2.3; it communicates only
through the compiled `.so` and a fixture file.

## Action abstraction *(milestone 6)*

An `Action` trait so a new integration is "implement the trait + register it,"
not a program rewrite. Extension guide lands here with the first real
integration.

## Compliance design *(milestone 7)*

Viewing-key / selective-disclosure scheme and the pluggable deposit-screening
hook, documented here when they land.

## Threat model *(milestone 8)*

Full, honest treatment of deanonymization vectors and residual leakage. The
summary in the [README](./README.md) is the current placeholder.

## Milestone status

| # | Milestone | State |
|---|-----------|-------|
| 1 | Workspace scaffold + CI + pinned Poseidon params | ✅ done |
| 2 | Membership circuit (arkworks) + tests | ✅ done |
| 3 | On-chain Groth16 verification + CU benchmark (~98k CU) | ✅ done |
| 4 | Merkle tree + `deposit` + root history | ⏳ next |
| 5 | Nullifier set + `execute_action` (no-op CPI) | ⏳ |
| 6 | Epochs + relayer + one real integration | ⏳ |
| 7 | Compliance (viewing keys + screening hook) | ⏳ |
| 8 | Threat model + docs + demo | ⏳ |
