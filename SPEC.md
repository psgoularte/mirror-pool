# mirror-pool — Build Spec (SPEC.md)

Authoritative spec for building the `mirror-pool` protocol. Paste this as your kickoff message to Claude Code, or commit it as `SPEC.md` at the repo root. Read **Engineering Standards** and **Do-NOT** before writing code.

---

## 0. Context & how to work

- The repo (`solanabr/mirror-pool`) is **empty** — only a `LICENSE` (MIT) and an initial commit, default branch `main`. You are building the whole thing from scratch. There is no existing architecture to conform to; you define it.
- This is a **contribution-based bounty**: you work in a fork and land work as **small, self-contained PRs against `solanabr:main`**, judged as the strongest contributor. Structure everything as a clean PR sequence.
- **Rust, end to end.** On-chain program, ZK circuit + prover, relayer, CLI — all Rust. No Circom, no JS/TS. There is **no GUI**; consumers are developers, agents, and other programs.
- **Move milestone by milestone.** Before milestone 1, briefly state the workspace layout you'll create, then build it. You do **not** need my confirmation between milestones — proceed, but after each, summarize what you built and paste the test/CI results.
- **Fail loud.** No mocked cryptography, no silent fallbacks, no `unwrap()`/`expect()`/`panic!` in on-chain instruction handlers (reserve panics for `#[cfg(test)]`). If something can't be done correctly, stop and say so rather than faking it.

---

## 1. What mirror-pool is

A shared **behavioral**-anonymity protocol — **not a fund mixer**. Members join a pool; when any member triggers a protocol interaction (a swap, a stake, etc.), the action is executed on-chain by the **pool program's PDA**, gated by a zero-knowledge proof of pool membership. Observers see that *an* action happened but cannot attribute it to a specific member. Larger pool + tighter per-epoch synchronization = stronger anonymity for everyone.

Architecturally this is an Elusiv/Tornado-style anonymity set (Merkle tree of commitments + nullifiers + ZK membership proof), generalized from "right to withdraw funds" to "right to trigger an action this epoch." The PDA — not the member — being the on-chain actor is the core unlinkability primitive.

---

## 2. Hard constraints (from the bounty)

- Rust only; MIT licensed (already in repo).
- **Production-grade**: robust typed errors, tests, reproducible build, deployable to devnet.
- **Scalable & customizable**: adding a new action (protocol integration) must be a small extension — implement a trait, not rewrite the program.
- **Realistic privacy**: must survive the obvious deanonymization vectors (fee-payer linkage, timing, single-member epochs). Document the threat model honestly, including what it does *not* defend against.
- **Well-documented**: clear `README` (what it is, threat model summary, install, quickstart), `ARCHITECTURE.md`, extension guide.

---

## 3. Tech stack (use exactly this unless you hit a concrete blocker; if so, flag it)

- **Circuit + prover (Rust, off-chain):** `arkworks` — `ark-relations`, `ark-groth16`, `ark-bn254`, `ark-crypto-primitives`. Groth16 over BN254. **Not Circom** — the bounty is Rust-only; arkworks keeps circuits in Rust while still producing BN254 Groth16 proofs.
- **On-chain verification:** `groth16-solana` (audited under Light Protocol v3), verifying BN254 Groth16 proofs via the `alt_bn128` syscalls in <200k compute units. Handle the big-endian byte layout and the `proof_a` negation quirk explicitly; confirm arkworks-produced proofs verify through it in milestone 3 before building anything on top.
- **Hashing:** Poseidon. **Critical footgun:** the Poseidon parameter set in the arkworks circuit MUST match the on-chain hasher (`sol_poseidon` syscall / `light-poseidon`) byte-for-byte. Pin the parameters in the `common` crate and assert equality in a test.
- **Program:** native `solana-program` (no Anchor) — keeps compute tight and matches the low-level bar. Anchor is an acceptable fallback for non-crypto plumbing only if a milestone is at time risk; flag before switching.
- **Relayer + CLI:** Rust (`solana-client`, `clap`).
- **Tests:** `cargo test` for the circuit; `litesvm` or `solana-program-test` for the program; a compute-unit benchmark test for verification.

---

## 4. Architecture

### 4.1 Membership circuit (arkworks, Groth16/BN254)
- **Private inputs:** `secret` (nullifier preimage), Merkle `path_elements[]`, `path_indices[]`.
- **Public inputs:** `merkle_root`, `nullifier_hash`, `epoch_id`, `action_binding` (hash of the intended action params).
- **Constraints:**
  1. `commitment = Poseidon(secret, …)` and Merkle-inclusion of `commitment` under `merkle_root`.
  2. `nullifier_hash = Poseidon(secret, epoch_id)` — epoch-scoped, so one membership acts once per epoch.
  3. Bind `action_binding` into the proof so a proof can't be replayed for a different action.
- **Tests:** valid proof verifies; wrong secret fails; tampered path fails; `action_binding` mismatch fails; replayed nullifier is rejected at program level.

### 4.2 On-chain program (native Rust)
State (PDAs):
- **Pool config:** tree params, root-history ring buffer, current epoch + epoch schedule, compliance-authority registry, fee params, upgrade authority.
- **Incremental Merkle tree** (fixed depth, Poseidon) with a root-history buffer so proofs against a recent root stay valid while the tree advances.
- **Nullifier set:** prevents double-action within an epoch.

Instructions:
- `initialize_pool(params)`
- `deposit(commitment)` → insert leaf, advance root, push to history; runs the (optional) screening hook.
- `open_epoch` / `close_epoch` (crank) → actions valid only inside their epoch window, forcing crowd synchronization.
- `execute_action(proof, public_inputs, action_params)` → verify Groth16 (`groth16-solana`); check root ∈ history; check epoch active; check nullifier unused; mark nullifier; **CPI to the target protocol signed by the pool PDA**.
- `register_viewing_key` / disclosure instruction → selective disclosure to an auditor.

### 4.3 Action abstraction (extensibility requirement)
Define an `Action` trait so a new integration = implement the trait + register it. Ship **one real integration** end-to-end (e.g., a Jupiter swap or a native stake) plus a trivial no-op action for tests. Document how to add one in `ARCHITECTURE.md`.

### 4.4 Relayer / coordinator (off-chain, Rust)
- **Relayer:** submits `execute_action` transactions and pays the fee, so the member's wallet is never the fee payer. **Core, not optional** — without it the fee payer trivially deanonymizes the action. Configurable fee cut.
- **Epoch batcher:** collects actions within an epoch and submits them clustered to maximize the per-window anonymity set.

### 4.5 CLI (Rust)
`keygen`, `deposit`, `prove` (arkworks prover), `execute` (via relayer), `disclose` (viewing-key proof), and `sim` (spin up N members; report the achieved anonymity-set size per epoch).

### 4.6 Compliance layer (first-class — the differentiator)
- **Viewing keys / selective disclosure:** a member can grant a designated auditor the ability to learn which actions they initiated, without weakening anyone else's anonymity.
- **Deposit-screening hook:** pluggable, off by default, able to reject entries based on an attestation/allowlist. Documented.
Frame all user-facing docs around *compliant behavioral privacy with selective disclosure*, not evasion.

---

## 5. Workspace layout

```
common/    # shared types + pinned Poseidon params (single source of truth)
circuit/   # arkworks membership circuit + prover
program/   # native Solana program (tree, nullifiers, epochs, PDA execution, compliance)
relayer/   # off-chain fee-paying relayer + epoch batcher
cli/       # keygen / deposit / prove / execute / disclose / sim
```

Cargo workspace at root. Shared crypto constants live only in `common` and are imported everywhere else.

---

## 6. Milestones = PR sequence

Each PR is atomic, tested, CI-green, and mergeable on its own. Conventional-commit titles; PR body states what/why + test evidence + CU numbers where relevant.

1. **Workspace scaffold + CI** (Cargo workspace, crate skeletons, GitHub Actions running fmt + clippy + test + `build-sbf`) + pinned Poseidon params in `common`. *This first PR sets the conventions the repo will follow — make it clean.*
2. **Membership circuit** (arkworks) + full unit tests incl. negative cases.
3. **On-chain verification** via `groth16-solana` + CU benchmark proving a real arkworks proof verifies under budget. Nothing builds on top until green.
4. **Merkle tree + `deposit`** with root-history buffer.
5. **Nullifier set + `execute_action`** gated by the proof, CPI to the no-op action via PDA.
6. **Epochs + relayer + one real protocol integration.**
7. **Compliance layer** (viewing keys / selective disclosure + screening hook).
8. **Threat model + docs + demo** (`README`, `ARCHITECTURE.md`, extension guide, `demo.sh`/`sim`).

---

## 7. Engineering standards

- Fail loud: every failure path returns a specific typed error; reject on unverifiable crypto; no swallowed errors, no default-to-empty on parse failure.
- No mocked cryptography — real proofs, real verification, real Poseidon. A stub is only a loud `todo!()` that fails the build path, never a fake success.
- Poseidon parameters asserted equal between circuit and chain (a test that fails if they drift).
- Keep the root-history buffer (proofs race tree updates without it).
- Negative/property tests are **mandatory** for every security-critical path: double-action, stale root, expired epoch, forged proof, param mismatch. Happy-path-only is a fail.
- Benchmark `execute_action` compute units; request an explicit CU budget; keep verification under ~200k.
- No `unwrap`/`expect`/`panic` in program handlers (test code excepted).

---

## 8. Threat model (a written deliverable, not an afterthought)

Document, in `README`/`ARCHITECTURE.md`, what deanonymizes a member and how the design mitigates each: single-member epochs, correlated timing across epochs, self-relaying that exposes the fee payer, dust/amount correlation. Be honest about residual leakage — an overclaimed privacy guarantee is worse than an accurate one.

---

## 9. Deliverables

- Compiling Cargo workspace with the crates above.
- `README.md`: what it is, threat-model summary, install, quickstart, devnet demo.
- `ARCHITECTURE.md`: component overview, the `Action` extension guide, compliance design.
- Test suite (circuit + program + CU benchmark) runnable with one command.
- A `demo.sh` or CLI `sim` running the full deposit → epoch → relayed action → selective-disclosure flow on a local validator.

---

## 10. Do-NOT

- Don't use Circom, JS, or TS anywhere (Rust-only rule).
- Don't let the member be the fee payer of the action tx.
- Don't mismatch Poseidon params between circuit and chain (assert equality).
- Don't skip the root-history buffer.
- Don't present a stubbed action as working — mark stubs loudly.
- Don't build a "defeat chain analysis / evade detection" framing into user-facing docs; frame it as compliant behavioral privacy with selective disclosure.
- Don't open one giant PR — small, focused, mergeable.

---

## 11. Start now

Begin with **milestone 1**: state the workspace layout you'll create (one short paragraph), then build the Cargo workspace + crate skeletons + CI + pinned Poseidon params in `common`. Then continue through the milestones, summarizing results after each. Write real, compiling, tested code — not pseudocode.