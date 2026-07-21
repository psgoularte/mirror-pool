# mirror-pool — VALIDATION.md

How we know the project actually works. Run these gates in order; a later gate assumes the earlier ones pass. **Each item is a gate, not a suggestion.**

## Read this first: why "tests pass" is not enough here

This project has two failure modes that stay invisible to a normal green test suite, so validation must be **adversarial** (try to break it), not **confirmatory** (show it works once):

1. **An under-constrained ZK circuit** compiles, produces proofs that verify, and passes happy-path tests — while still accepting *forged* proofs, because the constraints don't bind what you assumed. This is the #1 way ZK projects ship broken.
2. **A privacy failure is silent.** The system can run flawlessly and leak everything. Nothing in `cargo test` warns you that the real anonymity set is 1.

So: green tests are necessary and nowhere near sufficient. The gates that actually prove the project are the **negative tests** (Level 2) and the **observable-trace red-team** (Level 3). Never mock cryptography to make a gate pass — a mocked verifier makes forged proofs succeed silently, which is catastrophic.

---

## Level 0 — Build & toolchain sanity

- [ ] `cargo build` and `cargo build-sbf` both succeed; the program `.so` is produced.
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean.
- [ ] `cargo test --workspace` is green.
- [ ] CI runs all of the above on every PR and is green.

*Pass = all green. This is the floor, it proves almost nothing about correctness.*

---

## Level 1 — Functional correctness (happy path)

- [ ] Full end-to-end flow runs on a local validator via the CLI: `deposit → open_epoch → execute_action (via relayer) → disclose`. Provide this as `demo.sh` or the CLI `sim` command.
- [ ] A member who deposited can, in an open epoch, trigger the real integrated action, and it lands on-chain.
- [ ] `disclose` lets a designated auditor recover which actions a consenting member initiated, and fails for a non-authorized party.

*Pass = the happy paths exist and work once. Still weak evidence.*

---

## Level 2 — Cryptographic soundness (the real test)

These are the gates that matter. **Each of the following MUST be rejected** (a dedicated test asserting the failure):

- [ ] Proof generated with the **wrong secret** → rejected.
- [ ] Proof against a **stale/unknown Merkle root** (outside the root-history buffer) → rejected.
- [ ] **Reused nullifier** in the same epoch → rejected (double-action prevented).
- [ ] **`action_binding` mismatch** (proof valid but action params differ from what was bound) → rejected. This proves a proof can't be replayed for a different action.
- [ ] **Tampered Merkle path** → rejected.
- [ ] Proof valid for epoch N submitted in **epoch M** → rejected.

> If *any* of these is accepted, the project is broken even with every other test green. A passing negative test = the system correctly says "no".

Two cross-checks that catch the subtle bugs:

- [ ] **Verifier agreement:** the *same* arkworks-generated proof verifies identically off-chain (arkworks `Groth16::verify`) and on-chain (`groth16-solana`). A disagreement means an endianness/serialization bug in the on-chain path. Test both against the same fixture.
- [ ] **Poseidon parameter equality:** a test asserts the parameter set used by the circuit (in `common`) is byte-for-byte identical to the on-chain hasher (`sol_poseidon` / `light-poseidon`). This test must fail if the two ever drift.

- [ ] Grep the codebase for mocked/stubbed verification or hashing in any non-test path. There must be none. Stubs, if present, are loud `todo!()` that fail the build path — never a fake `Ok`.

---

## Level 3 — Privacy actually holds (observable-trace red-team)

No unit test covers this; you must attack the trace an on-chain observer would see.

- [ ] Run `sim` with N members over several epochs. Capture the **full public trace**: transactions, account metas, signers, **fee payers**, and timestamps — exactly what an explorer/chain-analysis tool sees.
- [ ] **Attempt the linkage yourself, with full knowledge:** can you map member → action from the public trace alone? If *you* can link it knowing the secrets, chain analysis can too. This must not be possible beyond the anonymity-set ambiguity.

Specific leaks to check (each is a hard fail):

- [ ] **Fee payer is always the relayer, never the member.** Assert this over the whole trace. A member-paid action is trivially deanonymizing.
- [ ] **Effective anonymity set per epoch > 1** (ideally ≫ 1). Compute and report it. An epoch with a single participant offers *zero* privacy despite a perfect ZK proof — the protocol must refuse to execute, delay, or clearly warn when the set is too small. Decide and enforce a minimum.
- [ ] **No unique linking key** in account metas, memo fields, amounts, or PDA-derivation seeds that ties an action back to a specific member.
- [ ] **Amount/dust correlation** doesn't re-link (if the action carries a value).
- [ ] **Timing** doesn't trivially re-link (batching/jitter within the epoch window is present, not deterministic per-member ordering).

- [ ] The **effective anonymity set per epoch** is reported as the project's headline privacy metric. This single number is the summary of whether the protocol keeps its promise.

---

## Level 4 — Solana deployability

- [ ] A **compute-unit benchmark test** measures `execute_action` CU and asserts it stays under budget. Groth16 verification (~200k) plus Merkle/nullifier ops must fit comfortably under the 1.4M cap.
- [ ] The transaction explicitly **requests its CU budget** (`ComputeBudgetInstruction`) rather than relying on the default.
- [ ] The proof + required accounts fit within transaction size limits.
- [ ] The program **deploys to devnet** and the e2e flow runs against the deployed program, not just a local test harness.

---

## Level 5 — Robustness / abuse resistance

- [ ] **Fuzz malformed inputs** (garbage proof bytes, wrong-length public inputs, malformed accounts): every case returns a **typed error**, never a `panic`/`unwrap` (a panic is a DoS vector) and never a false `Ok`.
- [ ] Re-initialization, unauthorized admin calls, and epoch-boundary edge cases are handled with explicit errors.

---

## External review (don't self-certify)

- [ ] Run **Superteam BR's `auditor-skill`** (their Solana security skill — 131 real-world attack vectors) against the program and address its findings. It's free, ecosystem-native, and catches bug classes you didn't think to test.
- [ ] Resolve or explicitly document every finding.

---

## Honesty gate (part of the threat-model deliverable)

- [ ] `README` / `ARCHITECTURE.md` states plainly **what the protocol does NOT protect against**: single-member epochs, correlated timing across epochs, self-relaying that exposes a fee payer, value/dust correlation, and the absence of a formal audit / formal circuit verification within this timeframe.
- [ ] No privacy claim is stronger than what Level 3 actually demonstrated. Overstating the guarantee is worse than documenting the limit — it leads someone to trust a protection that isn't there.

---

## Definition of Done (run as a confidence gradient)

The project is "functional and working" only when, in order:

1. Compiles + `build-sbf` + clippy/fmt clean (L0)
2. Happy-path e2e passes (L1)
3. **Every negative test fails as it should** (L2)
4. **Off-chain and on-chain verifiers agree** + Poseidon params asserted equal (L2)
5. **Trace red-team can't link member ↔ action** and the effective anonymity set is large (L3)
6. CU under budget + deploys and runs on devnet (L4)
7. Malformed inputs rejected with typed errors, no panics (L5)
8. `auditor-skill` findings resolved/documented
9. README honestly states the non-defenses (honesty gate)

Reaching only step 2 is a demo. Reaching step 5 is where it becomes a privacy tool. Reaching step 9 is where it's a defensible submission.