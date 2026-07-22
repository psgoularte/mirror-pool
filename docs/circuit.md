# Membership circuit & trusted setup

## The statement

The Groth16/BN254 circuit (`circuit::circuit::MembershipCircuit`) proves, in
zero knowledge: *"I know a secret whose commitment is a leaf under this Merkle
root, and this is its epoch-scoped nullifier"* — without revealing which leaf.

- **Private witness:** `secret`, `path_elements[20]`, `path_indices[20]`.
- **Public inputs (canonical order — load-bearing):** `merkle_root`,
  `nullifier_hash`, `epoch_id`, `action_binding`. The on-chain verifier consumes
  them in exactly this order.
- **Constraints:**
  1. `commitment = Poseidon(secret)`, and Merkle inclusion of `commitment` under
     `merkle_root` along the path;
  2. `nullifier_hash = Poseidon(secret, epoch_id)` — epoch-scoped, so a
     membership acts once per epoch;
  3. `action_binding` is pinned into the R1CS (a squaring constraint) so a proof
     cannot be replayed for a different action or parameters.

Negative tests (`circuit/tests/membership.rs`) cover wrong secret, tampered
path, action-binding mismatch, and wrong epoch — each with real proofs.

## Poseidon consistency (the critical invariant)

The circuit gadget, the native prover hasher, and the on-chain `sol_poseidon`
syscall must agree byte-for-byte, or a proof valid off-chain fails on-chain.
`common::poseidon` pins one circom-BN254 `x5` parameter set (from
`light-poseidon`, the implementation the syscall runs) and hand-rolls the
permutation reading the digest from `state[0]` — **not** arkworks'
`PoseidonSponge`, which reads `state[capacity]` and would silently diverge.
Tests assert gadget = native = light-poseidon = syscall.

## On-chain verification

`groth16-solana` verifies the proof via the `alt_bn128` syscalls (~98k CU). The
arkworks→on-chain conversion (`circuit::solana`) handles the three byte-layout
quirks: big-endian limbs, G2 `c1 || c0` ordering, and `proof_a` negation. The
program's verifier is byte-only (never links arkworks), which keeps it in budget.

## Trusted setup — multi-contributor Phase-2 ceremony

Groth16 needs a per-circuit setup whose secret randomness must be destroyed.
`circuit::ceremony` implements a real **multi-contributor Phase-2 MPC**: each
contributor re-randomizes the `delta` trapdoor with fresh entropy
(`delta_g1,g2 *= s`; the `delta`-divided `l_query`/`h_query` `*= s⁻¹`) and
publishes a Schnorr proof-of-contribution; a pairing same-ratio check ties the
`g1`/`g2` updates to one `s`. The key is secure **if at least one contributor
discarded their randomness**.

The committed ceremony (`setup/`) is verified by
`circuit/tests/trusted_setup.rs`: it replays and verifies the whole contribution
chain, pins the transcript by SHA-256, and confirms the committed on-chain VK is
the ceremony output. Correctness of the `delta` update is gated by
`ceremony::tests::ceremony_key_still_proves_and_verifies` (a full prove+verify
with the multi-contributed key).

**Honest scope.** Phase-2 re-randomizes `delta` only; `alpha, beta, gamma, tau`
come from the base setup (they would come from a universal **Phase-1**
powers-of-tau in production — the arkworks stack does not ingest an external
`.ptau`, so that Phase-1 is future work). The committed key's contributions were
run on one machine, so it is single-operator honest — suitable for review and
testnets, not for securing real value. See [`docs/security.md`](./security.md).
