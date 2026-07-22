# mirror-pool — VALIDATION results

Outcome of running every gate in [`VALIDATION.md`](./VALIDATION.md), refreshed
after the hardening pass. Each gate maps to the concrete test/binary that
enforces it. Reproduce with `./demo.sh` plus `cargo test --workspace`.

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
- **Effective anonymity set per epoch reported** (e.g. 6 distinct actions among 12 members) and must be > 1; `sim` reports it per epoch.
- **On-chain minimum**: `execute_action` refuses when the lower bound `members − actions_this_epoch < k_min` (`flow`: rejected at set=1<2, accepted at 2≥2).

> ⚠ **Honest limitation:** `k_min` bounds *program-visible* membership, **not**
> honest anonymity. Permissionless deposits let a Sybil adversary inflate the
> count; enable the screening hook or staked deposits for real use. Documented in
> `SECURITY.md` and the threat model. No privacy claim exceeds this.

## Level 4 — Solana deployability ✅ (devnet deploy deferred on funding)

- **CU under budget:** `cu-bench` (bench build) asserts `VerifyMembership < 200k` (measured **98,627**); `flow` asserts `execute_action < 200k` (measured ~108–116k). Far under the 1.4M cap.
- **Explicit CU request:** the relayer prepends `ComputeBudgetInstruction::set_compute_unit_limit`; `flow`/`cu-bench` too.
- **Tx size:** proof (256) + 4 public inputs (128) + accounts fit; all txs land.
- **Deploys and runs on a real validator:** the `--arch v3` artifact was deployed to a local `solana-test-validator` (real Agave 4.1.1) and the **full flow ran against the deployed program id over RPC** via the CLI — `init-pool`, `deposit`×2, `crank open`, and a relayer-paid `execute` (on-chain proof verification + PDA-signed CPI), each a confirmed transaction.
- **Live devnet:** **deferred** — the devnet CLI faucet was rate-limited during this work (both 2 SOL and 1 SOL refused). To finish: fund the address from `solana address` via a web faucet, then `solana program deploy … --url devnet` and re-run the CLI commands with `--url devnet`. The artifact and commands are identical to the validated localnet run.

## Level 5 — Robustness / abuse resistance ✅

- **Fuzz malformed inputs:** `program` `robustness.rs` throws thousands of random byte strings at `Instruction::unpack` and `ParsedVerifyingKey::parse` — never panics, always a typed error; truncated/oversized/wrong-tag inputs rejected. `verify_membership_absent_from_default_build` asserts the bench instruction is gone from the deployed build.
- **Re-initialization** → `Custom(6)`; **unauthorized crank** → `Custom(23)`; **epoch-not-active** → `Custom(21)`; **non-denominated transfer** → `Custom(26)`; **below k_min** → `Custom(25)` (all in `flow`).

## Hardening-pass gates (this round)

| Gate | Status | Evidence |
|---|---|---|
| Pool-scoped nullifiers | ✅ | `flow` "same nullifier hash spent independently in two pools" |
| Benchmark instruction removed from deployed artifact | ✅ | `#[cfg(feature="bench")]`; `verify_membership_absent_from_default_build` |
| On-chain minimum anonymity set (`k_min`) | ✅ | `flow` reject@1<2 / accept@2≥2; metric + limits in ARCHITECTURE |
| Amount privacy (denominations) | ✅ | `TransferAction` `DENOMINATIONS`; `flow` `Custom(26)` |
| Trusted-setup reproducibility | ✅ | committed `setup/verifying_key.solana.bin`; `circuit` `setup_reproducible` |
| Devnet deploy | ⚠ deferred | localnet real-validator deploy + RPC e2e done; devnet pending faucet funding |

## External review

Superteam BR's `auditor-skill` was **not available** in this environment. Two
independent structured reviews were run instead (documented as self-review, not
a third-party audit) — a base-protocol review and a hardening review. Neither
found a high-confidence exploitable vulnerability. Findings, resolutions, and the
inherent `k_min`/Sybil limitation are recorded in [`SECURITY.md`](./SECURITY.md).

## Honesty gate ✅

`README.md`, `ARCHITECTURE.md`, and `SECURITY.md` state plainly: no third-party
audit, no formal circuit verification, a **dev-only** trusted setup (with the
production ceremony path written out), the fee-payer/timing/amount/single-window
residual leakage, and — critically — that `k_min` does **not** guarantee honest
anonymity against a Sybil adversary. No privacy claim exceeds what Level 3 plus
the enforced on-chain invariant demonstrate.
