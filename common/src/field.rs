//! The protocol's scalar field and its canonical byte encoding.
//!
//! mirror-pool works over the BN254 scalar field `Fr`. On-chain the
//! `sol_poseidon` syscall and `groth16-solana` both consume **big-endian**
//! 32-byte limbs, so big-endian is the canonical wire encoding everywhere: the
//! circuit's public inputs, the Merkle leaves, and the program's account data
//! all agree on it. Keeping the conversion in one place removes a whole class
//! of endianness bugs.

use crate::error::{CommonError, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Byte length of a serialized field element / hash digest.
pub const FIELD_BYTES: usize = 32;

/// A canonical 32-byte big-endian field element (leaf, root, nullifier, …).
pub type Bytes32 = [u8; FIELD_BYTES];

/// Encode a field element as canonical big-endian bytes.
///
/// Always 32 bytes, zero-padded on the left, matching the on-chain layout.
pub fn fr_to_bytes_be(x: &Fr) -> Bytes32 {
    let be = x.into_bigint().to_bytes_be();
    // `to_bytes_be` already returns the minimal big-endian representation padded
    // to the field's limb width (32 bytes for BN254), so this is exact.
    let mut out = [0u8; FIELD_BYTES];
    debug_assert_eq!(be.len(), FIELD_BYTES);
    out.copy_from_slice(&be);
    out
}

/// Decode canonical big-endian bytes into a field element.
///
/// Rejects inputs of the wrong length and non-canonical encodings (values
/// `>=` the field modulus). We deliberately do **not** reduce mod p: a reducing
/// decoder would map two distinct 32-byte strings to the same element, which
/// would let an attacker forge a second valid encoding of a nullifier or root.
pub fn fr_from_bytes_be(bytes: &[u8]) -> Result<Fr> {
    if bytes.len() != FIELD_BYTES {
        return Err(CommonError::InvalidFieldLength(bytes.len()));
    }
    // `from_be_bytes_mod_order` reduces; to detect non-canonical input we
    // reduce, re-encode, and require the round-trip to be the identity.
    let candidate = Fr::from_be_bytes_mod_order(bytes);
    if fr_to_bytes_be(&candidate) != bytes {
        return Err(CommonError::NonCanonicalField);
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;

    #[test]
    fn roundtrip_is_identity() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(1);
        for _ in 0..256 {
            let x = Fr::rand(&mut rng);
            let bytes = fr_to_bytes_be(&x);
            assert_eq!(bytes.len(), FIELD_BYTES);
            assert_eq!(fr_from_bytes_be(&bytes).unwrap(), x);
        }
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            fr_from_bytes_be(&[0u8; 31]).unwrap_err(),
            CommonError::InvalidFieldLength(31)
        );
    }

    #[test]
    fn rejects_non_canonical() {
        // 0xFFFF...FF is far above the BN254 modulus, so it is non-canonical.
        let all_ones = [0xffu8; FIELD_BYTES];
        assert_eq!(
            fr_from_bytes_be(&all_ones).unwrap_err(),
            CommonError::NonCanonicalField
        );
    }
}
