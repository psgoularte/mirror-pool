# Security

mirror-pool is **unaudited** software implementing a zero-knowledge anonymity
protocol. Read this document before deploying anything you care about.

> **Top-line caveats**
> 1. **No third-party audit** and **no formal circuit verification** have been
>    performed.
> 2. The shipped verifying key is a **development** key from a single-party,
>    public-seed setup — **not production-trusted**. Anyone can forge proofs
>    against it. See [Trusted setup](#trusted-setup).
> 3. Privacy is **probabilistic and behavioral**, and depends on operational
>    conditions (busy epochs, a trusted relayer). See the
>    [threat model](./ARCHITECTURE.md#threat-model-milestone-8).

## Trusted setup

Groth16 needs a per-circuit trusted setup. The setup's secret randomness ("toxic
waste") must be destroyed; whoever retains it can forge membership proofs for the
pool (a **soundness** break — it does not by itself break privacy).

### What ships today (development)

`mirror_pool_circuit::prover::dev_setup()` runs arkworks' `circuit_specific_setup`
with a **fixed, public seed** (`DEV_SETUP_SEED`). This is deterministic on
purpose so the committed key (`setup/verifying_key.solana.bin`) is regenerable
and diffable in CI (`circuit`'s `setup_reproducible` test). Because the seed is
public, **this key is forgeable by anyone** and must never secure real value.

### Why not a real Phase-1 powers-of-tau here

The Rust/arkworks-only stack does not consume an external `.ptau` (perpetual
powers-of-tau) file: arkworks' Groth16 `circuit_specific_setup`/
`generate_parameters` sample all setup scalars internally from the provided RNG
rather than ingesting a Phase-1 transcript (that ingestion path is the
snarkjs/circom toolchain, which this project deliberately does not use). Reusing
a public Phase-1 would require either a snarkjs-compatible export of this circuit
or an arkworks-native MPC implementation. We do **not** fake this: the honest
status is a single-party dev setup, and the production path below is the required
work, not something already done.

### Production ceremony path (required before mainnet)

1. **Phase 1 (universal).** Start from a well-known public powers-of-tau
   transcript (e.g. the Perpetual Powers of Tau) sized for the circuit's
   constraint count, with published, independently-verified contributions.
2. **Phase 2 (circuit-specific).** Run a multi-party computation over *this*
   circuit where each contributor injects fresh entropy and publishes a
   contribution + proof-of-contribution; the final key is secure if **at least
   one** contributor was honest and discarded their randomness.
3. **Transcript & verification.** Publish every contribution and the final
   transcript; have independent parties verify the chain end-to-end.
4. **Pin the result.** Replace `setup/verifying_key.solana.bin` with the
   ceremony output, record the transcript hash here, and re-run
   `setup_reproducible` is **not** expected to pass afterward (the dev seed no
   longer reproduces it) — update that test to pin the ceremony key by hash.

Until that is done, treat every pool as a demo.

## Threat model

The full, honest deanonymization analysis — fee-payer linkage, single-action
windows, cross-epoch timing, amount/dust correlation, small pools, network-level
deanonymization, a malicious relayer, and a compromised setup — with mitigations
and residual leakage, lives in
[`ARCHITECTURE.md`](./ARCHITECTURE.md#threat-model-milestone-8). The one-line
summary: *mirror-pool hides which member acted, as strongly as the pool is large
and the epoch window is busy, provided a trusted relayer pays the fee.*

## Known limitations

- **No audit / no formal verification** (stated above).
- **Dev trusted setup** (stated above).
- **Anonymity-set minimum is a provable floor, not the exact set.** The on-chain
  invariant enforces `members_deposited − actions_this_epoch ≥ k_min`; the true
  anonymity set (an observer cannot link nullifiers to commitments) is generally
  larger, but the program only guarantees the floor.
- **Relayer trust.** The relayer learns the member↔action link by construction
  (it holds the job). Use a relayer you trust or a decentralized relayer set.
- **Global program upgrade authority** is out of scope here; a production
  deployment should use a governance-controlled or frozen upgrade authority.

## Security review

Superteam BR's `auditor-skill` was **not available in this build environment**.
In its place, independent structured reviews were run against the checklist
below. This is **self-review, not a third-party audit**, and is documented as
such.

### Checklist (each item reviewed)

- Authorization on every privileged instruction (`OpenEpoch`, `CloseEpoch`,
  `SetScreeningAuthority`): require `is_signer` **and** `authority == config.authority`.
- Account substitution / type confusion: PDAs (pool, nullifier, viewing record)
  re-derived with `find_program_address` and compared; `PoolConfig` loaded via
  `bytemuck::try_from_bytes` requires the exact `PoolConfig::LEN`, so smaller
  accounts cannot masquerade as a pool.
- Reentrancy / nullifier ordering: the nullifier marker is created before the
  action CPI; a reused nullifier is rejected.
- Action-binding completeness: selector **and** params (amount, recipient) are
  bound into the proof; the recipient account is checked against the bound key.
- Lamport arithmetic: `checked_sub`/`checked_add`, post-transfer rent-exemption
  enforced; only fixed denominations allowed.
- Signer-seed correctness for the PDA CPI: seeds rebuilt from the pool's own
  `authority`+`bump`.
- Anonymity-set counter integrity: `epoch_actions` increments only on the
  success path (rolled back with the transaction on any later error), resets on
  `open_epoch`, uses saturating arithmetic.

### Findings & resolutions

**Base protocol review (M1–M8).** No high-confidence exploitable vulnerability.
Two out-of-scope observations were raised and **resolved**:

1. *Global nullifier namespace* (cross-pool griefing, DoS-only) — **fixed** in
   the hardening pass: nullifier PDA seeds are now pool-scoped
   (`["nullifier", pool, hash]`).
2. *`VerifyMembership` read an unchecked VK account* (benchmark-only, no state
   change) — **fixed**: the instruction is now behind `#[cfg(feature = "bench")]`
   and is absent from the deployed artifact.

**Hardening review (pool-scoping, min-k, denominations, feature-gating).** No
concretely-exploitable finding. Verified correct: pool-scoped nullifier seed and
reuse rejection; `epoch_actions` increments only on the success path and rolls
back with the transaction on any later error (so a rejected action cannot leave
a phantom increment), resets on `open_epoch`, and uses saturating arithmetic;
the denomination check runs on the **proof-bound** amount, after the
action-binding check, so a relayer cannot substitute it; production instruction
discriminants (0..=7) are unchanged by the `bench` feature gate.

One **inherent limitation** (not a code bug), raised and documented rather than
"fixed": `k_min` bounds `members_deposited − actions_this_epoch`, which is a
floor on *program-visible* state, **not** on the *honest* anonymity set. Because
deposits are permissionless (screening off by default), an adversary can
Sybil-inflate `next_index` with self-controlled commitments to satisfy `k_min`
while the honest set is ~1, then subtract its own notes. This is the standard
Sybil limitation of every commitment-set anonymity design (Tornado/Elusiv). The
code enforces exactly what it claims; the honest-anonymity gap is a
**deployment/policy** concern (enable the screening hook, or require staked/
attested deposits) and is documented in the threat model. **Do not read `k_min`
as a guarantee of honest anonymity.**

## Responsible disclosure

This is a research/portfolio project without a production deployment. If you
find a security issue, please open a GitHub issue marked **security** (or, for
anything sensitive, contact the repository owner privately via their GitHub
profile) rather than disclosing an exploit publicly. There is no bug bounty.
