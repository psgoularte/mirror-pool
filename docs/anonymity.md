# Anonymity metric: min-entropy effective-k

mirror-pool measures the privacy an observer would actually infer from the
public trace — not a naive set size. The `anonymity` crate is a
**measurement/reporting instrument**; it is *never* an on-chain guarantee (the
on-chain floor is the cheap `k_min` count in the program).

## The metric

We report **min-entropy effective-k**:

```
effective_k = 2^{H∞} = 1 / maxᵢ pᵢ
```

where `pᵢ` is the adversary's posterior that participant *i* initiated an
observed action. `1 / max pᵢ` is exactly the bound on a **single-guess**
adversary's success probability — the honest worst case, not an average
(Serjantov & Danezis, PET 2002; Díaz, Seys, Claessens & Preneel, PET 2002;
Smith, FoSSaCS 2009).

## Which adversary (Part 2 precision)

Two adversaries give two figures, and the tool reports **both**:

- **External adversary** (no note ownership): every candidate is equally likely,
  `max pᵢ = 1/k`, so `uniform_effective_k = k`.
- **Dominant-funder adversary**: the single largest funder *knows its own `m`
  notes are not the honest target*, leaving `k − m` candidates, so
  `max pᵢ = 1/(k − m)` and `dominance_adjusted_effective_k = k − m`. This is the
  honest worst case, and why a Sybil-dominated bucket collapses (Sweeney 2002;
  Machanavajjhala et al. 2007; Li et al. 2007).

## Per bucket

An observer partitions actions by **denomination × action-type**; you are only
anonymous *within* your bucket. The tool reports the **worst-case effective-k
across buckets**, never a pooled figure that hides a thin one. (mirror-pool
deposits are not denomination-bound, so buckets do not thin the per-member set
*here*; the framework still reports per bucket for denomination-segregated
integrations and to flag single-action buckets.)

## Over the association set, not all deposits

An effective-k over *all* permissionless deposits is meaningless when the set is
Sybil-inflatable. We report it **over the attested/associated set** and **over
all deposits**; the delta is the **Sybil exposure**:

```
$ mirror-pool sim --members 16 --sybils 48 --actors 8
  effective-k over associated = 16.0, over all deposits = 64.0 (Sybil gap 48.0)
```

Only the association-set figure is an honest floor. This is why the anonymity
metric and the [association layer](./compliance.md) are one mechanism: the
association set is the precondition that makes the metric meaningful. See the
[threat model](../ARCHITECTURE.md#threat-model) for the residual `k_min`/Sybil
limitation — the metric quantifies it rather than hiding it.

## real-k: the headline figure (priced and measured)

The number `sim` leads with is **real-k = nominal − flagged**, where *flagged* is
the same-funder clustering above (the largest funder's notes discounted). It is
exactly the dominance-adjusted effective-k, surfaced as the headline so the
inflatable `nominal` count is never the primary figure:

```
$ mirror-pool sim --members 16 --sybils 48 --actors 8 --entry-fee 1000000000
  epoch 1: real-k = 16.0 (nominal 64, flagged 48); real-k over associated set = 15.0
  entry fee: inflating to nominal 64 with 48 sybils costs 48 × 1000000000 = 48 SOL
```

real-k is an **estimate**, not a guarantee: it discounts only the single largest
cluster, so an adversary who splits Sybils across many identities evades it. That
is why it is paired with the on-chain **entry fee** — `PoolConfig.entry_fee`
prices each identity (`s` Sybils cost `s × entry_fee`), so the cheap
single-funder inflation the heuristic catches and the split-identity inflation it
misses are *both* made costly. Neither prices nor measurement solves Sybil
resistance; together they narrow it honestly. See
[`security.md`](./security.md) for the residual.

## Behavior at scale (synthetic)

[`scale-analysis.md`](./scale-analysis.md) sweeps this same metric across pool
sizes (k up to 1000) and Sybil fractions, and overlays the entry-fee cost — a
reproducible, seeded analysis. It shows real-k growing with honest scale and
resisting concentrated-Sybil inflation. **The populations are synthetic**: it
measures how the metric behaves, not that a real crowd of that size will form —
which stays an operational open question.

## Why synchronized epochs (Anonymity Trilemma)

Epoch windows are not an arbitrary latency knob. The **Anonymity Trilemma** (Das,
Meiser, Mohammadi & Kate, IEEE S&P 2018; and the user-coordinated bound, PoPETs
2020) proves you cannot have strong anonymity, low bandwidth, and low latency at
once. mirror-pool spends **latency** — waiting for a busy shared window — to buy
anonymity at low bandwidth (no cover traffic). Effective-k grows with the number
of distinct actors that land in an open window; the operator trades window
duration for that count via `open_epoch`/`close_epoch`.

Full derivations and citations: [`ARCHITECTURE.md`](../ARCHITECTURE.md#references).
