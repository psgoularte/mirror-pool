//! Poseidon over BN254 — the single source of truth for mirror-pool's hashing.
//!
//! # Why this module exists
//!
//! The whole protocol is only sound if **three** Poseidon implementations agree
//! byte-for-byte:
//!
//! 1. the arkworks R1CS gadget inside the ZK circuit (`circuit` crate),
//! 2. the native prover-side hasher (this module), and
//! 3. the on-chain hasher — Solana's `sol_poseidon` syscall.
//!
//! If any two disagree, a proof that is valid off-chain fails on-chain (or, far
//! worse, a Merkle root the program computes never matches the one the circuit
//! proved membership under). The SPEC calls this out as the project's critical
//! footgun.
//!
//! We eliminate the risk by pinning **one** parameter set here and deriving
//! everything from it. The constants come from [`light_poseidon`]'s `bn254_x5`
//! table — the exact circom-compatible parameters that Light Protocol's
//! `sol_poseidon` syscall uses on-chain. This module re-implements the circom
//! permutation over those constants (so the circuit gadget has a plain-Rust
//! reference to match) and a test asserts it reproduces `light-poseidon`'s
//! output exactly. The circuit crate, in turn, tests its gadget against this
//! module. The chain of equalities closes the loop.
//!
//! The permutation here is a line-for-line port of `light_poseidon::Poseidon`'s
//! `hash`, kept explicit rather than delegating so the constants and the round
//! structure live in readable form next to the circuit gadget they mirror.

use crate::error::{CommonError, Result};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use light_poseidon::{parameters::bn254_x5::get_poseidon_parameters, PoseidonParameters};
use std::sync::OnceLock;

/// Poseidon arity used for a leaf commitment: `commitment = Poseidon(secret)`.
pub const ARITY_COMMITMENT: usize = 1;
/// Poseidon arity used for two-to-one Merkle hashing and the nullifier hash.
pub const ARITY_BINARY: usize = 2;

/// The pinned parameter set for a given arity (width = arity + 1).
///
/// This is exactly the type the circuit gadget consumes, so the round
/// constants and MDS matrix are shared verbatim — never re-typed.
pub type Params = PoseidonParameters<Fr>;

// Cached parameter sets. `light-poseidon`'s table lookup allocates, so we build
// each width once. Arity 1 -> width 2, arity 2 -> width 3.
static PARAMS_W2: OnceLock<Params> = OnceLock::new();
static PARAMS_W3: OnceLock<Params> = OnceLock::new();

/// Return the pinned Poseidon parameters for the given arity.
///
/// Only the arities the protocol actually uses (1 and 2) are supported; any
/// other value is a programming error and fails loudly rather than silently
/// falling back.
pub fn params_for_arity(arity: usize) -> Result<&'static Params> {
    match arity {
        ARITY_COMMITMENT => Ok(PARAMS_W2.get_or_init(|| {
            get_poseidon_parameters::<Fr>(2).expect("pinned bn254_x5 width-2 params must exist")
        })),
        ARITY_BINARY => Ok(PARAMS_W3.get_or_init(|| {
            get_poseidon_parameters::<Fr>(3).expect("pinned bn254_x5 width-3 params must exist")
        })),
        other => Err(CommonError::UnsupportedArity(other)),
    }
}

/// The circom Poseidon permutation over the pinned constants.
///
/// `state` has length `params.width`; `state[0]` is the (zero) domain tag and
/// `state[1..]` are the inputs on entry. On return `state` holds the permuted
/// value; the digest is `state[0]`. This mirrors
/// `light_poseidon::Poseidon::hash` exactly (see the module docs); the
/// `poseidon_matches_reference` test enforces that.
fn permute(state: &mut [Fr], params: &Params) {
    let alpha = [params.alpha];
    let full = params.full_rounds;
    let partial = params.partial_rounds;
    let half = full / 2;
    let width = params.width;

    let add_round_constants = |state: &mut [Fr], round: usize| {
        for (i, s) in state.iter_mut().enumerate() {
            *s += params.ark[round * width + i];
        }
    };
    let mix = |state: &mut [Fr]| {
        let mixed: Vec<Fr> = (0..width)
            .map(|i| (0..width).fold(Fr::ZERO, |acc, j| acc + state[j] * params.mds[i][j]))
            .collect();
        state.copy_from_slice(&mixed);
    };

    // First half: full S-box rounds.
    for round in 0..half {
        add_round_constants(state, round);
        for s in state.iter_mut() {
            *s = s.pow(alpha);
        }
        mix(state);
    }
    // Middle: partial rounds, S-box on state[0] only.
    for round in half..half + partial {
        add_round_constants(state, round);
        state[0] = state[0].pow(alpha);
        mix(state);
    }
    // Second half: full S-box rounds.
    for round in half + partial..full + partial {
        add_round_constants(state, round);
        for s in state.iter_mut() {
            *s = s.pow(alpha);
        }
        mix(state);
    }
}

/// Hash `inputs` with the pinned parameters, matching the on-chain hasher.
///
/// The arity is inferred from `inputs.len()` and must be a supported width.
pub fn hash(inputs: &[Fr]) -> Result<Fr> {
    let params = params_for_arity(inputs.len())?;
    let mut state = Vec::with_capacity(params.width);
    state.push(Fr::ZERO); // domain tag
    state.extend_from_slice(inputs);
    permute(&mut state, params);
    Ok(state[0])
}

/// `commitment = Poseidon(secret)` — the leaf inserted into the Merkle tree.
pub fn commitment(secret: Fr) -> Fr {
    hash(&[secret]).expect("arity 1 is supported")
}

/// `nullifier_hash = Poseidon(secret, epoch_id)` — epoch-scoped, so one
/// membership can act exactly once per epoch.
pub fn nullifier_hash(secret: Fr, epoch_id: Fr) -> Fr {
    hash(&[secret, epoch_id]).expect("arity 2 is supported")
}

/// Two-to-one hash of an internal Merkle node: `Poseidon(left, right)`.
pub fn hash_pair(left: Fr, right: Fr) -> Fr {
    hash(&[left, right]).expect("arity 2 is supported")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use light_poseidon::{Poseidon, PoseidonHasher};

    /// Reference hash via the upstream `light-poseidon` API (the exact
    /// implementation the `sol_poseidon` syscall runs on-chain).
    fn reference(inputs: &[Fr]) -> Fr {
        let mut hasher =
            Poseidon::<Fr>::new_circom(inputs.len()).expect("circom params for this arity");
        hasher.hash(inputs).expect("reference hash")
    }

    #[test]
    fn poseidon_matches_reference() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..1000 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            // arity 1
            assert_eq!(hash(&[a]).unwrap(), reference(&[a]), "arity-1 mismatch");
            // arity 2
            assert_eq!(
                hash(&[a, b]).unwrap(),
                reference(&[a, b]),
                "arity-2 mismatch"
            );
        }
    }

    #[test]
    fn helpers_agree_with_hash() {
        let s = Fr::from(123456789u64);
        let e = Fr::from(7u64);
        assert_eq!(commitment(s), hash(&[s]).unwrap());
        assert_eq!(nullifier_hash(s, e), hash(&[s, e]).unwrap());
        assert_eq!(hash_pair(s, e), hash(&[s, e]).unwrap());
    }

    #[test]
    fn rejects_unsupported_arity() {
        assert_eq!(
            hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]).unwrap_err(),
            CommonError::UnsupportedArity(3)
        );
    }

    #[test]
    fn deterministic() {
        let s = Fr::from(42u64);
        assert_eq!(commitment(s), commitment(s));
    }
}
