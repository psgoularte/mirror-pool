//! Poseidon as R1CS constraints — the in-circuit twin of
//! [`mirror_pool_common::poseidon`].
//!
//! This reproduces the circom permutation constraint-for-constraint over the
//! **same** pinned constants (`common` re-exports the `light-poseidon`
//! parameters, so the round constants and MDS matrix are shared verbatim, never
//! re-typed). Because the structure mirrors the native permutation exactly, a
//! witness that satisfies these constraints hashes to the identical field
//! element the prover and the on-chain `sol_poseidon` syscall compute. The
//! `gadget_matches_native` test enforces the equality directly.

use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;
use mirror_pool_common::poseidon::{params_for_arity, Params};

/// x^5 S-box: three constraints (`x²`, `x⁴`, `x⁴·x`).
fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

/// Multiply a variable by a field constant. This is a linear operation, so it
/// adds no R1CS constraint (arkworks folds `Constant * var` into the LC).
fn mul_const(x: &FpVar<Fr>, c: Fr) -> FpVar<Fr> {
    x * FpVar::constant(c)
}

/// Apply the MDS matrix: `new[i] = Σ_j mds[i][j] · state[j]` (all linear).
fn mix(state: &[FpVar<Fr>], params: &Params) -> Vec<FpVar<Fr>> {
    let width = params.width;
    (0..width)
        .map(|i| {
            let mut acc = FpVar::<Fr>::zero();
            for (j, s) in state.iter().enumerate() {
                acc += mul_const(s, params.mds[i][j]);
            }
            acc
        })
        .collect()
}

/// The circom Poseidon permutation in-circuit. `state` enters as
/// `[domain_tag, inputs…]` and is permuted in place; the digest is `state[0]`.
fn permute(state: &mut [FpVar<Fr>], params: &Params) -> Result<(), SynthesisError> {
    let full = params.full_rounds;
    let partial = params.partial_rounds;
    let half = full / 2;
    let width = params.width;

    let add_round_constants = |state: &mut [FpVar<Fr>], round: usize| {
        for (i, s) in state.iter_mut().enumerate() {
            *s += FpVar::constant(params.ark[round * width + i]);
        }
    };

    for round in 0..half {
        add_round_constants(state, round);
        for s in state.iter_mut() {
            *s = sbox(s)?;
        }
        let mixed = mix(state, params);
        state.clone_from_slice(&mixed);
    }
    for round in half..half + partial {
        add_round_constants(state, round);
        state[0] = sbox(&state[0])?;
        let mixed = mix(state, params);
        state.clone_from_slice(&mixed);
    }
    for round in half + partial..full + partial {
        add_round_constants(state, round);
        for s in state.iter_mut() {
            *s = sbox(s)?;
        }
        let mixed = mix(state, params);
        state.clone_from_slice(&mixed);
    }
    Ok(())
}

/// Hash `inputs` in-circuit, matching [`mirror_pool_common::poseidon::hash`].
///
/// The arity (`inputs.len()`) must be one the pinned parameters support; an
/// unsupported arity is a circuit-construction bug and surfaces as an
/// unsatisfiable-constraints error rather than a silent wrong hash.
pub fn hash_gadget(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let params = params_for_arity(inputs.len()).map_err(|_| SynthesisError::Unsatisfiable)?;
    let mut state = Vec::with_capacity(params.width);
    state.push(FpVar::<Fr>::zero()); // domain tag
    state.extend_from_slice(inputs);
    permute(&mut state, params)?;
    Ok(state[0].clone())
}

/// Two-to-one node hash in-circuit: `Poseidon(left, right)`.
pub fn hash_pair_gadget(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let inputs = [left.clone(), right.clone()];
    hash_gadget(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use mirror_pool_common::poseidon;

    #[test]
    fn gadget_matches_native() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        for _ in 0..25 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);

            // arity 1
            let cs = ConstraintSystem::<Fr>::new_ref();
            let av = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
            let out = hash_gadget(&[av]).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(out.value().unwrap(), poseidon::hash(&[a]).unwrap());

            // arity 2
            let cs = ConstraintSystem::<Fr>::new_ref();
            let av = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
            let bv = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();
            let out = hash_pair_gadget(&av, &bv).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(out.value().unwrap(), poseidon::hash(&[a, b]).unwrap());
        }
    }
}
