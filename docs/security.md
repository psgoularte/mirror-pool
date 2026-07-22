# Security

mirror-pool is **unaudited** software implementing a zero-knowledge anonymity
protocol. Read this document before deploying anything you care about.

> **Top-line caveats**
> 1. **No third-party audit** and **no formal circuit verification** have been
>    performed.
> 2. The shipped key comes from a **multi-contributor Phase-2 ceremony** whose
>    contributions were all run on **one machine** — secure if that single
>    operator was honest, plus a base (Phase-1) that rests on the same operator.
>    Suitable for review/testnets, **not** for securing real value. See
>    [Trusted setup](#trusted-setup).
> 3. Privacy is **probabilistic and behavioral**, and depends on operational
>    conditions (busy epochs, a trusted relayer). See the
>    [threat model](../ARCHITECTURE.md#threat-model).

Live-execution evidence (the deployed devnet program running the full flow and
rejecting the documented negatives, with on-chain-verifiable signatures) is in
[`PROOF.md`](./PROOF.md) — a functional proof on devnet, **not** a multi-party
soak, a production setup, or an audit.

## Trusted setup

Groth16 needs a per-circuit trusted setup. The setup's secret randomness ("toxic
waste") must be destroyed; whoever retains it can forge membership proofs for the
pool (a **soundness** break — it does not by itself break privacy).

### What ships (multi-contributor Phase-2)

`circuit::ceremony` implements a real **multi-contributor Phase-2 MPC**. Each
contributor re-randomizes the `delta` trapdoor with fresh, non-deterministic
entropy (`delta_g1,g2 *= s`; the `delta`-divided `l_query`/`h_query` `*= s⁻¹`)
and publishes a Schnorr proof-of-contribution; a pairing same-ratio check binds
the `g1`/`g2` updates to one `s`. The composed key is secure **if at least one
contributor discarded their randomness** — the real Groth16 assurance, replacing
the earlier forgeable public-seed dev key.

The committed ceremony lives in `setup/` (verifying key + `transcript/`).
`circuit/tests/trusted_setup.rs` **verifies the whole contribution chain**, pins
the transcript by SHA-256, and confirms the committed on-chain VK is the
ceremony output. Correctness of the `delta` update is gated by a full prove+
verify with the multi-contributed key
(`ceremony::tests::ceremony_key_still_proves_and_verifies`).

### What it does NOT yet cover

- **Single-operator contributions.** The shipped ceremony's contributions were
  all run on one machine (via `cli setup`), so it is only as honest as that one
  operator. A production ceremony coordinates contributions across **independent**
  parties, each publishing their contribution for public verification.
- **Phase-2 only.** The ceremony re-randomizes `delta`; `alpha, beta, gamma, tau`
  come from the base arkworks setup and rest on that base's entropy being
  discarded. The arkworks stack does **not** ingest an external `.ptau`, so a
  universal public **Phase-1** powers-of-tau is not wired in — that remains the
  production requirement. We do not fake it.

### Production ceremony path (before mainnet)

1. **Phase 1 (universal).** Start from a public powers-of-tau transcript (e.g.
   the Perpetual Powers of Tau), published and independently verified.
2. **Phase 2 (this circuit).** Run the `circuit::ceremony` contributions across
   **independent** machines/parties, each publishing their contribution.
3. **Verify + pin.** Publish the transcript; independent parties run
   `trusted_setup` to verify the chain; pin the transcript hash in that test.

Until independent multi-party contributions and a public Phase-1 are in place,
treat every pool as a testnet demo.

## Threat model

The full, honest deanonymization analysis — fee-payer linkage, single-action
windows, cross-epoch timing, amount/dust correlation, small pools, network-level
deanonymization, a malicious relayer, and a compromised setup — with mitigations
and residual leakage, lives in
[`ARCHITECTURE.md`](../ARCHITECTURE.md#threat-model). The one-line
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
- **Association-set compliance — partial.** The `associate` inclusion proof is a
  real ZK proof (reuses the membership circuit) and attests association-set
  membership only. **Exclusion (ZK non-membership) is not implemented on-chain**
  — only an off-chain native reference witness (`circuit::association::
  SanctionedSet`) is provided for the ASP flow; the ZK sorted-tree circuit is
  future work. Inclusion is verified **off-chain** (ASP-side); on-chain
  enforcement inside `execute_action` is a **design note, not code** (there is
  no feature-gated path for it in the program). Association sets **narrow** the
  Sybil gap (they make effective-k measurable over attested members) but do not
  eliminate it — a corrupt ASP re-introduces it.
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
