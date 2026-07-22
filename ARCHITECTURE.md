# mirror-pool architecture

This document covers the full protocol: the crypto foundation, the membership
circuit, on-chain verification, the tree/nullifier/epoch state machine, the
`Action` extension guide, the relayer, the compliance design, and the threat
model. All eight milestones are complete (see the status table at the end).

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

## On-chain state & tree (milestone 4)

`PoolConfig` (`program::state`) is the pool's account: the incremental Merkle
tree (current root + per-level `filled_subtrees`), the `ROOT_HISTORY_SIZE`
root-history ring buffer, and admin fields. Two design choices worth noting:

- **Zero-copy.** `PoolConfig` is a `bytemuck::Pod` cast directly out of the
  account buffer and mutated in place. It is ~3.4 KB — deserializing it by value
  (borsh) would overflow the 4 KB BPF stack frame. `u64` counters are stored as
  little-endian `[u8; 8]` to keep the struct `align = 1`, since account data is
  only byte-aligned.
- **Incremental insert.** `deposit` advances the tree in `TREE_DEPTH` Poseidon
  hashes using the filled-subtrees method, pushes the new root into the history
  ring, and never stores the whole tree. Hashing is the `sol_poseidon` syscall
  (`solana-poseidon`), so a root computed on-chain is byte-identical to the
  off-chain reference (`common::merkle`) and the root the circuit proves under.

Instructions added: `InitializePool` (creates the PDA `["pool", authority]`,
empty tree) and `Deposit` (insert a commitment). Measured cost: init ≈24k CU,
deposit ≈18.5k CU.

Correctness is gated by host tests (incremental root == reference root at every
step; on-chain Poseidon == `common::poseidon`; history eviction; tree-full) and
a litesvm end-to-end (`bench` `e2e` binary) that runs the real bytecode and
confirms the on-chain root matches the reference after several deposits.

## execute_action & the nullifier set (milestone 5)

`execute_action` is the protocol's core. Given a Groth16 membership proof and
its public inputs, the program (in order):

1. checks `epoch_id` equals the pool's current epoch (`EpochMismatch`);
2. checks `merkle_root` is a known recent root (`UnknownRoot`);
3. checks `action_binding == Poseidon(selector)` for the requested action, so a
   proof authorizes exactly one action (`ActionBindingMismatch`);
4. verifies the proof against the pool's embedded verifying key
   (`ProofVerificationFailed`);
5. rejects a reused `nullifier_hash` and otherwise creates its marker PDA
   (`["nullifier", nullifier_hash]`) — one action per membership per epoch
   (`NullifierAlreadyUsed`);
6. executes the action via a **PDA-signed CPI**.

**Nullifiers** are one PDA per `nullifier_hash`: existence = spent. This scales
without a growing central set and makes double-spend a simple "account already
exists" check. The fee payer is the relayer (any signer), never the member.

## Action abstraction (milestone 5, extended in 6)

The `Action` trait (`program::action`) is the extensibility seam. An action is
"what the pool PDA does on a member's behalf." Adding an integration means:

1. `impl Action for MyAction` — `selector()` and `execute(&ActionContext)`,
   where `execute` performs one or more **PDA-signed CPIs** (the pool signs, so
   the member is never the actor);
2. add one arm to `action::dispatch`;
3. define the action's parameter layout and fold it into the action binding.

Milestone 5 ships `NoOpAction` (a self-CPI proving the pool PDA signs) and the
`no-op` selector. Milestone 6 adds `TransferAction`, a real integration that
disburses SOL from the pool PDA to a recipient with the **amount and recipient
bound into the proof** (`action_binding = Poseidon(selector, sha256(params))`).

### Adding an integration (extension guide)

To integrate protocol X (a swap, a stake, a lending deposit):

1. Define `struct XAction;` and `impl Action for XAction`. `selector()` returns
   a fresh stable byte; `execute(&ctx)` builds the CPI(s) into X's program and
   calls `invoke_signed(&ix, &infos, &[ctx.pool_seeds])` — the pool PDA signs,
   so X sees the pool, never the member. (`NoOpAction` is the reference shape;
   `TransferAction` shows param handling.)
2. Add `SELECTOR_X => Ok(Box::new(XAction))` to `action::dispatch`.
3. Define X's parameter byte layout; the caller passes it as `action_params`,
   and it is automatically folded into the action binding, so a proof authorizes
   exactly those parameters.

No change to the proof, nullifier, epoch, or Merkle machinery is required.

## Epochs (milestone 6)

`open_epoch` / `close_epoch` are authority-only cranks. `execute_action` is
accepted only while an epoch is open **and** the proof's `epoch_id` equals the
pool's `current_epoch`. This forces actions to cluster inside a shared window:
the anonymity set for an action is the set of members who acted in the same open
epoch, so tighter windows with more participants mean stronger anonymity.
Nullifiers are epoch-scoped (`Poseidon(secret, epoch_id)`), so each membership
can act once per epoch.

## Relayer & epoch batcher (milestone 6)

The `relayer` crate is **core, not optional**: it submits `execute_action` and
**pays the fee**, so the member's wallet is never the fee payer (self-relaying
trivially deanonymizes — see the threat model). A member produces a `RelayJob`
(proof + public inputs + action + accounts) with the CLI and hands it to a
relayer out of band; the relayer signs as the sole fee payer and submits. The
`batch` subcommand submits every job in a directory within one window — the
epoch batcher — and reports the achieved per-window anonymity-set size. The
relayer keeps its Solana stack on the 2.3 line (matching the program) and never
crosses Solana types with the program — it uses the program only for the borsh
instruction encoding and PDA seed constants.

The full flow (initialize → deposit → open epoch → prove → no-op action →
transfer action → close epoch), plus the negatives (replay, action-binding
mismatch, tampered proof, wrong epoch, epoch-not-active), runs against the real
SBF bytecode in the `bench` `flow` binary. Measured: `open`/`close` ≈1.5k CU,
`execute_action` ≈110k CU.

## Compliance design (milestone 7)

The compliance layer is the differentiator, framed as **compliant behavioral
privacy with selective disclosure**, not evasion.

### Viewing keys / selective disclosure

An auditor holds an X25519 **viewing keypair**. To disclose to that auditor, a
member seals their `secret` to the auditor's public key
(`common::compliance::seal_disclosure`, ECIES over X25519 + ChaCha20-Poly1305).
The `register_viewing_key` instruction stores a `DisclosureRecord` at the PDA
`["viewing", commitment]`: the member's commitment, the designated auditor, and
the sealed secret. The auditor later reads it, opens the secret
(`open_disclosure`), and for any epoch verifies that a given on-chain
`nullifier_hash = Poseidon(secret, epoch)` was theirs (`verify_disclosure`),
attributing the action.

Properties: disclosure is **per-member, per-auditor**. One member disclosing to
one auditor reveals nothing about any other member; there is no master key and
no way to enumerate non-disclosing members. The sealed secret is public but
opens only to the named auditor. Real-world identity is bound separately by the
member attesting to their `commitment`.

### Deposit-screening hook

`PoolConfig.screening_authority` is all-zero by default (**screening off**).
`set_screening_authority` (authority only) enables it; then every `deposit` must
be co-signed by that authority, which is rejected otherwise
(`ScreeningRequired`). The authority is pluggable: point it at the authority of
an allowlist/attestation program that only co-signs deposits for vetted
entrants. This gates entry without touching the anonymity mechanics.

Both are exercised against the real bytecode by the `bench` `compliance` binary:
an unscreened deposit is rejected, a screened one accepted, a disclosure is
registered on-chain, the auditor recovers the secret and attributes the
nullifier, and a stranger cannot.

## Threat model (milestone 8)

mirror-pool provides **probabilistic, behavioral** anonymity. Your anonymity set
for an action is the set of pool members who could plausibly have produced it —
cryptographically, *every* member, but in practice narrowed by the operational
factors below. An overclaimed guarantee is worse than an accurate one, so this
section is explicit about residual leakage and about what the protocol does
**not** defend.

### What the cryptography guarantees

Given an honest trusted setup and the Poseidon/Groth16 soundness, an observer of
the chain learns, per action: that *some* member of the tree (under a recent
root) performed action X in epoch E, and a `nullifier_hash` that is unlinkable to
any commitment without the member's secret. They do **not** learn which leaf,
which depositor, or any link between two actions by the same member across
epochs (nullifiers are `Poseidon(secret, epoch)` — distinct and unlinkable per
epoch). Double-acting in one epoch is prevented by the nullifier set.

### Deanonymization vectors and mitigations

| Vector | How it deanonymizes | Mitigation | Residual leakage |
|---|---|---|---|
| **Fee-payer linkage** | If the member's own wallet pays the action fee, the fee payer *is* the member. | The **relayer** is mandatory: it is the sole fee payer and signer of `execute_action`. The member's key never appears. | The relayer learns the member↔action link (it holds the job). Use a relayer you trust, or a relayer network; never self-relay. |
| **Single-action windows** | If only one action lands in an epoch, an observer correlating deposits/epochs can narrow the actor. | Epoch windows (`open`/`close`) batch actions; the epoch batcher clusters submissions; `sim` reports the realized per-window count. | A thin window is weak. The protocol surfaces the count rather than hiding it — operators should keep windows busy. |
| **Timing correlation** | Deposit→action latency, or repeated same-time behavior across epochs, can re-link a member. | Epoch batching decouples action time from any single member; per-epoch nullifiers prevent cross-epoch linkage of the *same* nullifier. | Behavioral timing patterns across epochs are **not** fully hidden. Documented as residual. |
| **Amount / dust correlation** | For value-carrying actions (the transfer), a unique amount links input to output. | Bind amount into the proof (done) and use **denominated** amounts per integration so many members share the same amount. | Non-denominated or unique amounts leak. The transfer action allows arbitrary amounts; denomination is an integration-level policy, documented. |
| **Anonymity-set size** | A tiny pool means few candidates. | Depth-20 tree (~1M capacity); `sim` reports the set size and warns on tiny pools. | Early in a pool's life the set is small. Wait for the pool to fill. |
| **Trusted setup** | A retained setup secret ("toxic waste") lets an attacker forge membership proofs. | Documented requirement: production keys from a multi-party ceremony; the dev `setup` is for local use only. | If the ceremony is compromised, soundness (not privacy) breaks. Out of protocol scope. |
| **Screening authority** | If enabled, the screening authority sees who deposits. | Off by default; when on, it is scoped to *entry* only and never sees actions. | Enabling screening trades some deposit-time privacy for compliance — an explicit, opt-in choice. |

### What mirror-pool does NOT defend against

- **Network-level deanonymization** (IP correlation of the submitter): use the
  relayer over an anonymizing transport; out of protocol scope.
- **A malicious or logging relayer**: it knows the member↔action link by
  construction. Trust or decentralize the relayer.
- **Global passive adversaries doing statistical disclosure** over long horizons
  with thin windows and unique amounts: mitigated, not eliminated.
- **Compromised trusted setup**: breaks soundness; requires a proper ceremony.

### Assurance status (honesty gate)

- **No formal audit.** This code has not undergone a third-party security audit.
- **No formal circuit verification.** Circuit soundness is argued by construction
  and covered by adversarial negative tests (wrong secret, tampered path,
  stale/unknown root, reused nullifier, action-binding mismatch, wrong epoch —
  each with a dedicated failing case), but not machine-checked.
- **Dev trusted setup only.** The keys `cli setup` produces are for local use;
  production requires a multi-party ceremony that discards the toxic waste.
- **Minimum anonymity set is not enforced on-chain** (it cannot be — the count of
  future actions in a window is unknown at execution time). It is surfaced by
  `sim`/the relayer and must be enforced operationally (keep windows busy).

The honest one-line summary: *mirror-pool hides which member acted, as strongly
as the pool is large and the epoch window is busy, provided a trusted relayer
pays the fee.*

## Milestone status

| # | Milestone | State |
|---|-----------|-------|
| 1 | Workspace scaffold + CI + pinned Poseidon params | ✅ done |
| 2 | Membership circuit (arkworks) + tests | ✅ done |
| 3 | On-chain Groth16 verification + CU benchmark (~98k CU) | ✅ done |
| 4 | Merkle tree + `deposit` + root history | ✅ done |
| 5 | Nullifier set + `execute_action` (no-op CPI) | ✅ done |
| 6 | Epochs + relayer + one real integration | ✅ done |
| 7 | Compliance (viewing keys + screening hook) | ✅ done |
| 8 | Threat model + docs + demo (`demo.sh`, CLI `sim`) | ✅ done |
