# mirror-pool — VALIDATION results

Outcome of running every gate in [`VALIDATION.md`](./VALIDATION.md). Each gate is
mapped to the concrete test/binary that enforces it, so the claims are
reproducible. Run everything with `./demo.sh` plus `cargo test --workspace`.

## Level 0 — Build & toolchain sanity ✅

- `cargo build` + `cargo build-sbf` succeed; `target/deploy/mirror_pool_program.so` is produced.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean (workspace **and** the excluded `bench/` crate).
- `cargo test --workspace` green.
- CI (`.github/workflows/ci.yml`) runs all of the above on every PR, plus `build-sbf`, the CU benchmark, the e2e, the full flow, compliance, and the privacy trace.

## Level 1 — Functional correctness (happy path) ✅

- Full flow on an in-process local SVM (litesvm) against the real bytecode: `bench` `flow` binary and `demo.sh` — initialize → deposit → open_epoch → `execute_action` (no-op via relayer-paid tx) → real transfer → close_epoch.
- A deposited member triggers the real integrated action (`TransferAction`); it lands and the recipient receives the funds from the pool PDA.
- `disclose`: the `compliance` binary shows a designated auditor recovering the member's actions and a non-authorized party failing.

## Level 2 — Cryptographic soundness ✅ (the real test)

Every case below has a dedicated assertion that the system says **no**:

| Must be rejected | Where | Result |
|---|---|---|
| Wrong secret | `circuit/tests/membership.rs::wrong_secret_fails` | rejected |
| Stale/unknown Merkle root | `bench` `flow` "stale/unknown root" | `Custom(13)` UnknownRoot |
| Reused nullifier (same epoch) | `bench` `flow` "replay" | `Custom(16)` NullifierAlreadyUsed |
| `action_binding` mismatch | `bench` `flow` "action-binding mismatch" | `Custom(15)` |
| Tampered Merkle path | `circuit/tests/membership.rs::tampered_path_*` | unsatisfiable |
| Proof for epoch N used in epoch M | `bench` `flow` "wrong epoch" | `Custom(14)` EpochMismatch |

Cross-checks:

- **Verifier agreement:** `circuit/src/solana.rs::offchain_and_onchain_verifiers_agree` — the *same* proof verifies via arkworks `Groth16::verify` and via `groth16-solana`, and both reject the same tampered input.
- **Poseidon parameter equality:** `common::poseidon::poseidon_matches_reference` (common == `light-poseidon`) and `program`'s `tree_logic::onchain_poseidon_matches_common` (the `sol_poseidon`/`solana-poseidon` path == common). Drift fails the test.
- **No mocked crypto:** `grep` over all non-test `src/` finds no `todo!`/`unimplemented!`/`mock`/`stub`/fake `Ok`, and no `unwrap`/`expect`/`panic` in program code (crate-level `deny`).

## Level 3 — Privacy actually holds (observable-trace red-team) ✅

`bench` `trace` binary runs a multi-member epoch through a **dedicated relayer** and attacks the public trace:

- **Fee payer is always the relayer, never a member** — asserted over every action tx. Members have no keypair in the action path.
- **No member is a signer** on any action tx.
- **No account meta / PDA seed is member-derived** — asserted the trace contains no member commitment; nullifier PDAs are per-action and unlinkable without the secret.
- **Effective anonymity set per epoch is reported** as the headline metric (e.g. 6 distinct actions among 12 members) and must be > 1; the CLI `sim` reports it per epoch and warns on single-action (timing-vulnerable) windows.
- Amount/dust: the transfer amount is bound into the proof; denomination is an integration policy (documented).

## Level 4 — Solana deployability ⚠️ (one gate not run here)

- **CU benchmark asserts under budget:** `bench` `cu-bench` asserts `VerifyMembership < 200k` (measured ~98k); `flow` asserts `execute_action < 200k` (measured ~110k). Both far under the 1.4M cap.
- **Explicit CU request:** the relayer prepends `ComputeBudgetInstruction::set_compute_unit_limit` (`relayer::EXECUTE_ACTION_CU_LIMIT`); the `flow`/`cu-bench` txs do too.
- **Tx size:** proof (256) + 4 public inputs (128) + accounts fit; all flow txs land.
- **Devnet deploy:** NOT executed in this environment (no funded devnet keypair). The litesvm gates run the **identical `.so`** that `solana program deploy` would upload. Deploy commands are in the README; this is the single gate deferred to the operator.

## Level 5 — Robustness / abuse resistance ✅

- **Fuzz malformed inputs:** `program/tests/robustness.rs` throws thousands of random byte strings at `Instruction::unpack` and `ParsedVerifyingKey::parse` — never panics, always a typed error or `Ok`; truncated/oversized/wrong-tag inputs are rejected.
- **Re-initialization** rejected (`bench` `flow` → `Custom(6)` AlreadyInitialized).
- **Unauthorized admin crank** rejected (`bench` `flow` → `Custom(23)` NotPoolAuthority).
- **Epoch-boundary:** acting while no epoch is open is rejected (`Custom(21)` EpochNotActive).

## External review

- Superteam BR's `auditor-skill` was **not available in this build environment**. An independent security review of the on-chain handlers was run instead (authorization, account-substitution, reentrancy/nullifier-ordering, action-binding, lamport handling, signer-seeds). Findings and resolutions are recorded below.

**Outcome: no high-confidence (≥8) exploitable vulnerability found.** The
reviewer traced every handler against nine Solana/ZK vulnerability classes and
confirmed the following are correctly handled:

- **Pool/VK/root/epoch/signer consistency** — in `execute_action` the verifying
  key, epoch, root history, and the CPI signer seeds (`authority`+`bump`) all come
  from the *same* ownership-checked `pool_account`; no cross-pool substitution
  (a smaller nullifier/viewing account can't masquerade as a pool — `bytemuck`
  requires the exact `PoolConfig::LEN` buffer). A forged-VK pool can only move its
  own lamports.
- **Nullifier-before-CPI** — the nullifier marker is created before the action
  CPI, so no reentrant double-spend window.
- **Action binding** — selector, amount, and recipient are all proof-bound; the
  relayer cannot alter them, and the recipient account is checked against the
  bound key.
- **Lamport handling** — `checked_sub`/`checked_add` + post-transfer
  rent-exemption enforcement.
- **Authorization** — epoch cranks and screening require both `is_signer` and
  `authority == config.authority`; re-init and PDA re-derivation guards present.

Two minor observations, both **non-vulnerabilities** (documented as known
limitations, not fixed):

1. **Global nullifier namespace.** Nullifier PDA seeds are
   `["nullifier", hash]` with no pool discriminator, so nullifiers are shared
   across pools under one program. This only enables cross-pool griefing (a DoS,
   which is out of scope) and makes double-spend prevention strictly *stronger*.
   For multi-pool deployments, add the pool key to the seed.
2. **`VerifyMembership` reads an unchecked VK account.** It is the side-effect-free
   M3 compute-unit benchmark instruction (verify + log only), so an
   attacker-supplied VK changes no state.

## Honesty gate ✅

`ARCHITECTURE.md` states plainly what the protocol does **not** protect against
(fee-payer linkage / self-relaying, single-action windows, cross-epoch timing,
amount/dust correlation, small pools, network-level deanonymization, a malicious
relayer, a compromised trusted setup) and its **assurance status** (no formal
audit, no formal circuit verification, dev-only trusted setup, anonymity-set
minimum enforced operationally not on-chain). No privacy claim exceeds what
Level 3 demonstrates.
