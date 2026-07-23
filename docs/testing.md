# Testing & acceptance evidence

How mirror-pool is known to work, and how to reproduce it. The project was
developed against an adversarial acceptance checklist (green tests are necessary
but not sufficient for a ZK/privacy system); the levels below are that checklist,
each mapped to the concrete test or binary that enforces it.

**Reproduce everything:** `./demo.sh` (end-to-end on the real SBF bytecode via an
in-process validator) plus `cargo test --workspace`. Compute-unit numbers and
the effective-k Sybil-gap demo are called out inline.

## Level 0 — Build & toolchain sanity ✅

- `cargo build` + `cargo build-sbf --arch v3` succeed; the deployable
  `target/deploy/mirror_pool_program.so` is produced (default features → the
  benchmark-only `VerifyMembership` instruction is **not** in it).
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean (workspace **and** the excluded `bench/` crate). `#![deny(missing_docs)]` on the `common` and `circuit` libraries.
- `cargo test --workspace` green (default = deployed feature set).
- CI runs fmt + clippy(all-features) + test(default), then a `build-sbf (v3)` job that runs the flow/compliance/trace binaries and, on a separate `--features bench` build, the CU benchmark.

## Level 1 — Functional correctness (happy path) ✅

- Full flow against the real bytecode (litesvm) and, additionally, against a
  **real Agave validator** over RPC via the CLI (see L4): initialize → deposit →
  open_epoch → `execute_action` (relayer-paid) → real transfer → disclose.
- The `TransferAction` disburses a denominated amount from the pool PDA.
- `disclose`: the `compliance` binary shows the designated auditor recovering the
  member's actions and a non-authorized party failing.

## Level 2 — Cryptographic soundness ✅

Every case has a dedicated assertion that the system says **no**:

| Must be rejected | Where | Result |
|---|---|---|
| Wrong secret | `circuit` `membership::wrong_secret_fails` | rejected |
| Stale/unknown Merkle root | `flow` "stale/unknown root" | `Custom(13)` |
| Reused nullifier | `flow` "replay" | `Custom(16)` |
| `action_binding` mismatch | `flow` "action-binding mismatch" | `Custom(15)` |
| Tampered Merkle path | `circuit` `membership::tampered_path_*` | unsatisfiable |
| Proof for epoch N in epoch M | `flow` "wrong epoch" | `Custom(14)` |

Cross-checks:

- **Verifier agreement:** `circuit` `solana::offchain_and_onchain_verifiers_agree` — the same proof verifies via arkworks `Groth16::verify` and via `groth16-solana`, and both reject the same tampered input.
- **Poseidon parameter equality:** `common::poseidon::poseidon_matches_reference` and `program` `tree_logic::onchain_poseidon_matches_common`.
- **No mocked crypto:** grep over non-test `src/` finds no `todo!`/`mock`/`stub`/fake `Ok`; no `unwrap`/`expect`/`panic` in program code.

## Level 3 — Privacy actually holds (observable-trace red-team) ✅

`bench` `trace` runs a multi-member epoch through a **dedicated relayer** and
attacks the public trace:

- **Fee payer is always the relayer**, never a member (members have no keypair in the action path).
- **No member signer** on any action tx; **no member-derived account/PDA seed** in the trace.
- **Effective anonymity set per epoch reported** as **min-entropy effective-k** (`anonymity` crate), per denomination×action-type bucket, **over the association set and over all deposits** — `cli sim` prints both and the Sybil-gap delta (e.g. 16 associated vs 64 all → gap 48), plus the dominance-adjusted figure.
- **On-chain minimum**: `execute_action` refuses when the lower bound `members − actions_this_epoch < k_min` (`flow`: rejected at set=1<2, accepted at 2≥2).

> ⚠ **Honest limitation:** `k_min` bounds *program-visible* membership, **not**
> honest anonymity. Permissionless deposits let a Sybil adversary inflate the
> count; enable the screening hook or staked deposits for real use. Documented in
> [`security.md`](./security.md) and the threat model. No privacy claim exceeds this.

## Level 4 — Solana deployability ✅ (live on devnet)

- **CU under budget:** `cu-bench` (bench build) asserts `VerifyMembership < 200k` (measured **98,634** by the current `demo.sh`); `flow` asserts `execute_action < 200k` (measured ~108–116k; 108,367 observed on-chain, see [`PROOF.md`](./PROOF.md)). Far under the 1.4M cap.
- **Explicit CU request:** the relayer prepends `ComputeBudgetInstruction::set_compute_unit_limit`; `flow`/`cu-bench` too.
- **Tx size:** proof (256) + 4 public inputs (128) + accounts fit; all txs land.
- **Deploys and runs on a real validator:** the `--arch v3` artifact was deployed to a local `solana-test-validator` (real Agave 4.1.1) and the **full flow ran against the deployed program id over RPC** via the CLI — `init-pool`, `deposit`×2, `crank open`, and a relayer-paid `execute` (on-chain proof verification + PDA-signed CPI), each a confirmed transaction.
- **Live devnet:** **deployed and exercised end-to-end** — program id `4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe` ([explorer](https://explorer.solana.com/address/4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe?cluster=devnet)). Init → 3 deposits → open → 2 relayer-paid `execute_action`s (on-chain Groth16 verify, **108,367 CU** measured on-chain) → close, plus `NullifierAlreadyUsed` and `AnonymitySetTooSmall` rejected live, all with `Finalized` signatures in [`PROOF.md`](./PROOF.md). See also [`deployment.md`](./deployment.md).

## Level 5 — Robustness / abuse resistance ✅

- **Fuzz malformed inputs:** `program` `robustness.rs` throws thousands of random byte strings at `Instruction::unpack` and `ParsedVerifyingKey::parse` — never panics, always a typed error; truncated/oversized/wrong-tag inputs rejected. `verify_membership_absent_from_default_build` asserts the bench instruction is gone from the deployed build.
- **Re-initialization** → `Custom(6)`; **unauthorized crank** → `Custom(23)`; **epoch-not-active** → `Custom(21)`; **non-denominated transfer** → `Custom(26)`; **below k_min** → `Custom(25)`; **entry fee omitted/underpaid** → `Custom(27)` (all in `flow`).

## Hardening-pass gates (this round)

| Gate | Status | Evidence |
|---|---|---|
| Pool-scoped nullifiers | ✅ | `flow` "same nullifier hash spent independently in two pools" |
| Benchmark instruction removed from deployed artifact | ✅ | `#[cfg(feature="bench")]`; `verify_membership_absent_from_default_build` |
| On-chain minimum anonymity set (`k_min`) | ✅ | `flow` reject@1<2 / accept@2≥2; metric + limits in ARCHITECTURE |
| Amount privacy (denominations) | ✅ | `TransferAction` `DENOMINATIONS`; `flow` `Custom(26)` |
| Trusted setup — distributable, independently verifiable Phase-2 | ✅ | `circuit::ceremony` MPC (contributor id bound into the PoK + prior-state hash chaining); `cli ceremony-init/contribute/finalize` distribute it, `cli verify-setup` checks the chain from public data; `circuit` `trusted_setup` pins the transcript hash **and asserts independent-contributor count = 1**; `distinct_contributors_are_counted_independently`, `reattributing_a_contribution_is_rejected`, `ceremony_key_still_proves_and_verifies`. **Shipped key = 1 independent contributor (single operator) → testnet-grade.** |
| Devnet deploy | ✅ | live program id `4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe` on devnet; localnet real-validator deploy + RPC e2e |

## Addendum v2 — research-grounded anonymity + compliance

| Gate | Status | Evidence |
|---|---|---|
| Min-entropy effective-k (`1/max pᵢ`) | ✅ | `anonymity` crate unit tests; `cli sim` |
| Per-bucket (denomination×action-type), worst bucket | ✅ | `anonymity::measure`; reported by `sim` |
| Over associated set **and** over all deposits; Sybil-gap delta | ✅ | `sim`: 16 vs 64, gap 48; `sybil_gap_is_reported` test |
| Dominance/homogeneity adjustment (`k − max-funder`) | ✅ | `dominance_shrinks_effective_k` test |
| Anti-Sybil entry fee (priced) | ✅ | `PoolConfig.entry_fee`; `flow` entry-fee section: omitted/underpaid → `Custom(27)`, paid accepted, vault +fee; `entry_fee=0` reproduces prior behavior (whole flow runs fee=0) |
| real-k reporting (measured) | ✅ | `anonymity` `real_k_is_nominal_minus_flagged` + `sybil_cost_scales_with_fee`; `cli sim` headlines real-k with `--entry-fee` pricing |
| Anonymity Trilemma justification of epochs | ✅ (doc) | ARCHITECTURE "Synchronized rounds & the Anonymity Trilemma" + References |
| Association-set **inclusion** proof (ZK) | ✅ | `circuit::association` tests; `cli associate` self-verifies; outsider/wrong-root rejected |
| Association-set **exclusion** | ⚠ off-chain reference only | `SanctionedSet::exclusion_witness` (native); ZK on-chain circuit documented as future work |
| Selective disclosure (viewing keys) | ✅ | `compliance` binary (from M7) |
| Citations from primary papers | ✅ | ARCHITECTURE "References" (PET'02, FoSSaCS'09, k/l/t-anonymity, Trilemma S&P'18/PoPETs'20, Privacy Pools'23) |

**Honest scope (unchanged, deepened):** the effective-k figure is a measurement,
**not** an on-chain guarantee (the on-chain floor is the `k_min` count). The
association layer makes effective-k meaningful over attested members and
**narrows** the Sybil gap but does not eliminate it (a corrupt ASP re-introduces
it). Exclusion is an off-chain reference, not a ZK on-chain proof. No overclaim.

## External review

Superteam BR's `auditor-skill` was **not available** in this environment. Two
independent structured reviews were run instead (documented as self-review, not
a third-party audit) — a base-protocol review and a hardening review. Neither
found a high-confidence exploitable vulnerability. Findings, resolutions, and the
inherent `k_min`/Sybil limitation are recorded in [`security.md`](./security.md).

## Honesty gate ✅

`README.md`, `ARCHITECTURE.md`, and [`docs/security.md`](./security.md) state
plainly: no third-party audit, no formal circuit verification, a
**single-operator** multi-contributor Phase-2 ceremony with no external Phase-1
(secure if ≥1 contributor was honest, but run on one machine — testnet-grade),
the fee-payer/timing/amount/single-window residual leakage, and — critically —
that `k_min` does **not** guarantee honest anonymity against a Sybil adversary.
No privacy claim exceeds what Level 3 plus the enforced on-chain invariant
demonstrate.
