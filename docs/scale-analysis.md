# Scale analysis (synthetic)

How the anonymity **metric** behaves as the pool grows — measured over
**synthetic** populations with the same min-entropy machinery used everywhere
else (`crates/anonymity`, see [`anonymity.md`](./anonymity.md)).

## Honesty block (read first)

- **What this shows.** effective-k / real-k trajectories vs. pool size and vs.
  Sybil fraction, plus the cost the `entry_fee` imposes to reach each nominal
  size. It uses the exact metric already validated by unit tests — no second
  anonymity number is invented.
- **What this does NOT show.** Real independent users. The participants are
  **synthetic**; nobody has demonstrated that real people will join and act in
  the **same epoch** at these sizes. That is an **operational open question**,
  not something this analysis answers.
- **No overclaim.** Nothing here is "proven private at scale." It is *the metric,
  measured over synthetic populations.* A large synthetic effective-k does not
  imply a large real anonymity crowd.

## Method & distribution assumptions

Reproduce (deterministic; the seed is recorded):

```sh
cargo run -p mirror-pool-cli --release -- scale            # prints the tables below
cargo run -p mirror-pool-cli --release -- scale --csv out  # also writes CSV
```

Default **seed = `0x5CA1E` (379422)**. Under the model below the reported figures
are a deterministic function of `(honest size, Sybil count, adversary strategy)`;
the seed derives a single uniform *salt* added to every funder id, which shifts
all ids equally and therefore **cannot change clustering** — results are
seed-invariant. The seed is consumed and recorded for reproducibility and for
future stochastic funder models; we say so rather than implying variance it does
not create.

Population model (the same `Note { funder, associated }` the metric consumes):

- **Honest members** are modeled as **independently funded** — a distinct
  `funder` each. This is the optimistic honest case (also the assumption in the
  crate's tests and `sim`). Because real-k discounts the single largest
  same-funder cluster, an all-distinct honest set gives `real-k = k − 1`.
- **Sybils** are modeled two ways:
  - **concentrated** — one funder controls *all* Sybils (the largest cluster the
    real-k heuristic discounts);
  - **split** — one funder per Sybil, which **evades** the largest-cluster
    heuristic and shows why the per-identity `entry_fee` is the needed complement.
- **Metric.** `effective-k = 1/maxᵢ pᵢ` (min-entropy); `real-k = nominal −
  largest same-funder cluster` (= the dominance-adjusted effective-k). One
  observable bucket is used (mirror-pool deposits are not denomination-bound, so
  the candidate set is the whole scoped note set).

## [1] Pool size (honest only) — privacy grows with honest scale

| honest-k | nominal-k | effective-k | real-k |
|---------:|----------:|------------:|-------:|
| 10       | 10        | 10.0        | 9.0    |
| 50       | 50        | 50.0        | 49.0   |
| 100      | 100       | 100.0       | 99.0   |
| 500      | 500       | 500.0       | 499.0  |
| 1000     | 1000      | 1000.0      | 999.0  |

real-k rises linearly with honest scale (`k − 1`). The caveat stands: this is the
metric over *synthetic* honest members — it assumes those members exist and act
in one epoch, which is the operational open question.

## [2] Sybil pressure at honest-k = 100 — real-k resists inflation

Sybil fraction `f` = Sybils / nominal. `entry_fee = 1 SOL` for the cost overlay.

| sybil% | sybils | nominal-k | real-k (concentrated) | real-k (split) | gap | inflate cost |
|-------:|-------:|----------:|----------------------:|---------------:|----:|-------------:|
| 0%     | 0      | 100       | 99.0                  | 99.0           | 1.0 | 0 SOL        |
| 25%    | 33     | 133       | 100.0                 | 132.0          | 33.0 | 33 SOL      |
| 50%    | 100    | 200       | 100.0                 | 199.0          | 100.0 | 100 SOL    |
| 75%    | 300    | 400       | 100.0                 | 399.0          | 300.0 | 300 SOL    |

Reading:

- **real-k (concentrated)** stays pinned to the honest floor (~100) no matter how
  many Sybils are added — the metric is **not fooled** by single-funder inflation,
  while **nominal-k** balloons. The `gap` (nominal − real-k) is the Sybil
  exposure, now shown as a curve.
- **real-k (split)** tracks nominal instead — a **limitation**, honestly shown: an
  adversary who spreads Sybils across distinct identities evades the
  largest-cluster heuristic.
- **Entry-fee overlay** is why that limitation is not the end of the story:
  reaching a given nominal-k costs `sybils × entry_fee` (`inflate cost`)
  **regardless of how the Sybils are split**. Measurement (real-k) catches the
  cheap concentrated attack; economics (`entry_fee`) prices the split attack.
  Neither "solves" Sybil resistance — see [`security.md`](./security.md).

## What this does and doesn't settle

It settles that the *metric* scales sensibly: real-k grows with honest
participation, is not inflated by concentrated Sybils, and its blind spot (split
identities) is exactly the one the entry fee prices. It does **not** settle that
a real crowd of this size will form — recruiting real independent users who
deposit and act within a shared epoch is an operational question this synthetic
analysis cannot answer.
