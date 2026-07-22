//! Off-chain **anonymity measurement** for mirror-pool.
//!
//! This crate computes the honest privacy metric an observer would infer from
//! the public trace. It is a **measurement / reporting instrument** — it is
//! never asserted as an on-chain guarantee. The on-chain floor stays the cheap
//! `k_min` count in the program; this crate reports the richer, adversarial
//! figure so operators can see the real exposure.
//!
//! # What it measures
//!
//! The reported quantity is **min-entropy effective-k**,
//! `effective_k = 2^{H∞} = 1 / maxᵢ pᵢ`, where `pᵢ` is the adversary's posterior
//! that participant *i* initiated an observed action. `1/max pᵢ` is exactly the
//! bound on a single-guess adversary's success probability — the honest
//! worst-case, not the average. (Serjantov & Danezis, *Towards an
//! Information-Theoretic Metric for Anonymity*, PET 2002; Díaz, Seys, Claessens
//! & Preneel, *Towards Measuring Anonymity*, PET 2002; Smith, *On the
//! Foundations of Quantitative Information Flow*, FoSSaCS 2009, for the
//! min-entropy / single-guess measure.)
//!
//! Three honesty-preserving refinements, all reported explicitly:
//!
//! 1. **Over the association set, not all deposits.** Measuring over *all*
//!    permissionless deposits is meaningless when the set is Sybil-inflatable
//!    (the documented `k_min` limitation). We report effective-k over the
//!    attested/associated deposits *and* over all deposits; **the delta is the
//!    Sybil exposure** the threat model names.
//! 2. **Per bucket.** An observer partitions actions by
//!    `denomination × action-type`; you are only anonymous *within* your bucket.
//!    We report the **worst-case effective-k across buckets**, never a pooled
//!    figure that hides a thin bucket.
//! 3. **Dominance / homogeneity — and which adversary.** Two adversaries give
//!    two figures, both reported:
//!    * **External** adversary (no note ownership): every candidate is equally
//!      likely, `max pᵢ = 1/k`, so `uniform_effective_k = k`.
//!    * **Dominant-funder** adversary: the single largest funder, who *knows its
//!      own `m` notes are not the honest target*, is left with `k − m`
//!      candidates, so `max pᵢ = 1/(k − m)` and
//!      `dominance_adjusted_effective_k = k − m`. This is the honest worst case
//!      and the reason a Sybil-dominated bucket collapses.
//!    (Sweeney, *k-anonymity*, 2002; Machanavajjhala et al., *l-diversity*,
//!    2007; Li, Li & Venkatasubramanian, *t-closeness*, ICDE 2007.)
//!
//! Pure Rust, no Solana/arkworks dependencies.

use std::collections::BTreeMap;

/// The observable bucket an action falls into: an observer can always see the
/// denomination and the action type, and can only confuse you with others in
/// the same bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket {
    /// Fixed denomination in lamports (0 for value-less actions such as no-op).
    pub denomination: u64,
    /// Action selector (no-op, transfer, …).
    pub action_type: u8,
}

/// One deposited note that is a *candidate* initiator, from an observer's view.
#[derive(Clone, Copy, Debug)]
pub struct Note {
    /// The entity that funded this note. A colluding-funder adversary knows
    /// which notes it funded and can exclude them when attributing an honest
    /// action. Distinct funders model independent participants.
    pub funder: u64,
    /// Whether this note is in the curated association set (clean provenance).
    pub associated: bool,
}

/// Min-entropy effective-k from a posterior distribution: `1 / max pᵢ`.
///
/// Returns `0.0` for an empty distribution. Non-normalized inputs are
/// normalized first (so raw candidate counts can be passed as weights).
pub fn min_entropy_effective_k(weights: &[f64]) -> f64 {
    let total: f64 = weights.iter().copied().filter(|w| *w > 0.0).sum();
    if total <= 0.0 {
        return 0.0;
    }
    let max_p = weights.iter().copied().fold(0.0_f64, f64::max) / total;
    if max_p <= 0.0 {
        0.0
    } else {
        1.0 / max_p
    }
}

/// Per-bucket anonymity figures.
#[derive(Clone, Debug)]
pub struct BucketReport {
    /// The bucket these figures are for.
    pub bucket: Bucket,
    /// Number of candidate notes in the bucket (nominal set size).
    pub nominal_k: usize,
    /// **External-adversary** min-entropy effective-k: no note ownership, every
    /// candidate equally likely, so `max pᵢ = 1/k` and this equals `nominal_k`.
    pub uniform_effective_k: f64,
    /// **Dominant-funder-adversary** effective-k: the largest single funder
    /// knows its own `m` notes are not the honest target, leaving
    /// `nominal_k − max_funder_notes` candidates (`max pᵢ = 1/(k−m)`). The
    /// honest worst case.
    pub dominance_adjusted_effective_k: f64,
    /// Share of the bucket controlled by its largest funder (0.0–1.0).
    pub top_funder_share: f64,
}

/// Effective-k over one candidate scope (all deposits, or the associated set).
#[derive(Clone, Debug)]
pub struct ScopeReport {
    /// Per-bucket figures.
    pub buckets: Vec<BucketReport>,
    /// The worst (smallest) uniform effective-k across all buckets — the honest
    /// headline for this scope.
    pub worst_uniform_effective_k: f64,
    /// The worst dominance-adjusted effective-k across all buckets.
    pub worst_dominance_adjusted_effective_k: f64,
}

/// A full epoch measurement: the same computation over the associated set and
/// over all deposits, plus the Sybil-exposure delta between them.
#[derive(Clone, Debug)]
pub struct EpochReport {
    /// Measured over deposits in the association set (the honest figure).
    pub over_associated: ScopeReport,
    /// Measured over all deposits (Sybil-inflatable; optimistic).
    pub over_all: ScopeReport,
}

impl EpochReport {
    /// Sybil exposure: how much the worst-bucket effective-k is inflated by
    /// counting unassociated (potentially Sybil) deposits. A large positive
    /// value means the "all deposits" figure is not trustworthy.
    pub fn sybil_gap(&self) -> f64 {
        self.over_all.worst_uniform_effective_k - self.over_associated.worst_uniform_effective_k
    }
}

fn scope_report(notes: &[Note], buckets_present: &[Bucket]) -> ScopeReport {
    // In mirror-pool a member is not bound to a denomination at deposit, so the
    // candidate set for an action in ANY bucket is the whole (scoped) note set.
    // We still report per bucket so that (a) denomination-segregated
    // integrations get a real per-bucket thinning, and (b) a bucket with very
    // few observed actions is flagged as timing-distinguishable by the caller.
    let mut per_funder: BTreeMap<u64, usize> = BTreeMap::new();
    for n in notes {
        *per_funder.entry(n.funder).or_default() += 1;
    }
    let nominal_k = notes.len();
    let max_funder = per_funder.values().copied().max().unwrap_or(0);
    let uniform = nominal_k as f64;
    let dominance = (nominal_k.saturating_sub(max_funder)) as f64;
    let top_share = if nominal_k == 0 {
        0.0
    } else {
        max_funder as f64 / nominal_k as f64
    };

    let buckets: Vec<BucketReport> = buckets_present
        .iter()
        .map(|b| BucketReport {
            bucket: *b,
            nominal_k,
            uniform_effective_k: uniform,
            dominance_adjusted_effective_k: dominance,
            top_funder_share: top_share,
        })
        .collect();

    // Worst across buckets (here identical per bucket; the min is robust for
    // segregated designs where candidate sets differ per bucket).
    let worst_uniform = buckets
        .iter()
        .map(|b| b.uniform_effective_k)
        .fold(f64::INFINITY, f64::min);
    let worst_dom = buckets
        .iter()
        .map(|b| b.dominance_adjusted_effective_k)
        .fold(f64::INFINITY, f64::min);
    ScopeReport {
        buckets,
        worst_uniform_effective_k: if worst_uniform.is_finite() {
            worst_uniform
        } else {
            0.0
        },
        worst_dominance_adjusted_effective_k: if worst_dom.is_finite() {
            worst_dom
        } else {
            0.0
        },
    }
}

/// Measure an epoch: `notes` are the candidate deposits, `buckets_present` are
/// the `denomination × action-type` buckets an observer sees actions in.
pub fn measure(notes: &[Note], buckets_present: &[Bucket]) -> EpochReport {
    let associated: Vec<Note> = notes.iter().copied().filter(|n| n.associated).collect();
    EpochReport {
        over_associated: scope_report(&associated, buckets_present),
        over_all: scope_report(notes, buckets_present),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_entropy_uniform_equals_n() {
        // Uniform over n → effective-k = n.
        assert!((min_entropy_effective_k(&[1.0, 1.0, 1.0, 1.0]) - 4.0).abs() < 1e-9);
        assert_eq!(min_entropy_effective_k(&[]), 0.0);
    }

    #[test]
    fn min_entropy_skewed_is_dominated_by_max() {
        // One participant with 90% posterior → effective-k ≈ 1.11, not 4.
        let k = min_entropy_effective_k(&[0.9, 0.04, 0.03, 0.03]);
        assert!((k - 1.0 / 0.9).abs() < 1e-9);
        assert!(k < 1.2);
    }

    #[test]
    fn dominance_shrinks_effective_k() {
        // 10 notes, one funder controls 7 → dominance-adjusted = 3.
        let mut notes = vec![
            Note {
                funder: 0,
                associated: true
            };
            7
        ];
        notes.extend((1..4).map(|f| Note {
            funder: f,
            associated: true,
        }));
        let b = [Bucket {
            denomination: 0,
            action_type: 0,
        }];
        let r = measure(&notes, &b);
        assert_eq!(r.over_associated.worst_uniform_effective_k, 10.0);
        assert_eq!(r.over_associated.worst_dominance_adjusted_effective_k, 3.0);
    }

    #[test]
    fn sybil_gap_is_reported() {
        // 3 honest associated notes + 20 unassociated Sybils (one funder).
        let mut notes = vec![
            Note {
                funder: 1,
                associated: true,
            },
            Note {
                funder: 2,
                associated: true,
            },
            Note {
                funder: 3,
                associated: true,
            },
        ];
        notes.extend((0..20).map(|_| Note {
            funder: 99,
            associated: false,
        }));
        let b = [Bucket {
            denomination: 1_000_000_000,
            action_type: 1,
        }];
        let r = measure(&notes, &b);
        assert_eq!(r.over_associated.worst_uniform_effective_k, 3.0);
        assert_eq!(r.over_all.worst_uniform_effective_k, 23.0);
        // The "all deposits" figure is inflated by 20 — that is the Sybil gap.
        assert_eq!(r.sybil_gap(), 20.0);
        // And over ALL, the dominance-adjusted figure collapses (one funder owns
        // the 20 Sybils): 23 - 20 = 3.
        assert_eq!(r.over_all.worst_dominance_adjusted_effective_k, 3.0);
    }
}
