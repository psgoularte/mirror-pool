# Security

mirror-pool is **unaudited** software implementing a zero-knowledge anonymity
protocol. Read this document before deploying anything you care about.

> **Top-line caveats**
> 1. **No third-party audit** and **no formal circuit verification** have been
>    performed.
> 2. The shipped key comes from a Phase-2 ceremony that is now **distributable
>    and independently verifiable** (`cli verify-setup`), but the committed key
>    has **exactly 1 independent contributor** (a single operator on one machine)
>    — so it is secure only if that one operator was honest, and the base
>    (Phase-1) rests on the same operator. Suitable for review/testnets, **not**
>    for securing real value. See [Trusted setup](#trusted-setup).
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

### What ships (distributable, independently verifiable Phase-2)

`circuit::ceremony` implements a real **multi-contributor Phase-2 MPC**. Each
contributor re-randomizes the `delta` trapdoor with fresh, non-deterministic
entropy (`delta_g1,g2 *= s`; the `delta`-divided `l_query`/`h_query` `*= s⁻¹`)
and publishes a Schnorr proof-of-contribution; a pairing same-ratio check binds
the `g1`/`g2` updates to one `s`. Each contribution also records its
**contributor id** (bound into the Fiat–Shamir challenge, so it can't be
re-attributed) and a **prior-state hash** chaining it to its predecessor. The
composed key is secure **if at least one contributor discarded their randomness**.

**Distributable.** The ceremony can be run across **independent operators** with
no shared secret: `ceremony-init` publishes base params + an empty transcript;
each operator runs `ceremony-contribute` (fetch params + transcript, inject fresh
OS entropy, emit a PoK, publish the updated params + transcript) — passing only
public data to the next; `ceremony-finalize` derives the verifying key. See
[`circuit.md`](./circuit.md) for the commands.

**Independently verifiable.** Anyone can check the whole chain from public data
(transcript + verifying key) with **`cli verify-setup`** — it runs every
same-ratio and Schnorr check, confirms the chain produces the committed key,
prints each contributor and the **independent-contributor count**, and prints the
transcript hash. `circuit/tests/trusted_setup.rs` additionally pins that hash by
SHA-256 and asserts the independent count. Correctness of the `delta` update is
gated by a full prove+verify with the multi-contributed key
(`ceremony::tests::ceremony_key_still_proves_and_verifies`).

### Independent contributors in the shipped key: **1** (single operator)

The committed key in `setup/` has **exactly one independent contribution**, from:

- `mirror-pool-maintainer (single operator, one machine, 2026-07)` — id
  `e8844a74…68af4428`.

**Running N contributions yourself on one machine does not upgrade this** — one
operator who saw all the entropy is cryptographically a single-party setup, so we
ship (and count) exactly one. The **precise assurance** is therefore: *secure iff
that one contributor was honest and discarded their entropy* — i.e. currently
"trust the maintainer." That is why the key stays **testnet-grade**. The win of
this pass is the *verifiable, distributable ceremony infrastructure* and the
accurate count, **not** a larger number.

### What remains for production

- **More independent contributors.** Have genuinely separate parties each run
  `ceremony-contribute` and publish their contribution; the assurance strengthens
  to "≥1 of *these* independent parties was honest." The tooling supports this
  today — only independent operators are missing.
- **Public Phase-1.** The ceremony re-randomizes `delta`; `alpha, beta, gamma,
  tau` come from the base arkworks setup and rest on that base's entropy being
  discarded. The arkworks stack does **not** ingest an external `.ptau`, so a
  universal public **Phase-1** powers-of-tau is not wired in. We do not fake it.
- **Published attestations.** Contributor ids are recorded and bound; signed
  human attestations per contribution are a straightforward future addition.

Until there are multiple independent contributors and a public Phase-1, treat
every pool as a testnet demo.

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
  larger, but the program only guarantees the floor. The Sybil-inflation gap in
  that floor is **priced** by the optional `entry_fee` and **measured** by real-k
  (see the Security-review section below) — priced and measured, not solved.
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
- **Not demonstrated with a real crowd at scale.** Anonymity depends on a real,
  busy epoch; no live deployment has shown a large crowd of independent users
  depositing and acting together. The **metric** is now *analyzed* at scale over
  **synthetic** populations ([`scale-analysis.md`](./scale-analysis.md)) — real-k
  grows with honest scale, resists concentrated-Sybil inflation, and its
  split-identity blind spot is the one the `entry_fee` prices — but synthetic
  participants are **not** a real crowd. Whether real independent users will join
  and act in the same epoch remains an **operational open question**.
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

**Mitigation — priced and measured, not solved.** Two additive mechanisms
narrow this gap without pretending to close it:

1. **Entry fee (prices it).** `PoolConfig.entry_fee` (an init parameter; `0` =
   off, the default, reproducing permissionless deposits exactly) charges a
   per-deposit fee, paid into the pool PDA (the fee vault) via a program-issued
   system transfer as a precondition of `deposit`. Underpayment is rejected with
   `EntryFeeUnpaid` (`Custom(27)`). This makes Sybil inflation *cost real
   lamports per fake identity* — inflating to nominal `k` with `s` Sybils costs
   `s × entry_fee` — but it does **not** make it impossible; a funded adversary
   can still pay. It raises the cost; it is not a cryptographic barrier.
2. **real-k (measures it).** The `anonymity` crate and `cli sim` now headline
   **real-k = nominal − flagged**, where *flagged* is the transparent same-funder
   clustering heuristic already used for the dominance-adjusted effective-k (the
   single largest funder's notes are discounted). real-k is an operator/observer
   **estimate** of honest anonymity, **not** a guarantee: an adversary who splits
   Sybils across many distinct funding identities evades the heuristic — which is
   precisely why it is paired with the entry fee that prices each identity.

Neither mechanism "solves" Sybil resistance. The residual above stands; the fee
prices the attack and real-k reports the honest floor instead of the inflatable
nominal count.

## Responsible disclosure

This is a research/portfolio project without a production deployment. If you
find a security issue, please open a GitHub issue marked **security** (or, for
anything sensitive, contact the repository owner privately via their GitHub
profile) rather than disclosing an exploit publicly. There is no bug bounty.
