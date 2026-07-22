//! Compliance primitives — **compliant behavioral privacy with selective
//! disclosure**, not evasion.
//!
//! # Viewing keys / selective disclosure
//!
//! A member can grant a designated auditor the ability to learn which on-chain
//! actions *they* initiated, without weakening anyone else's anonymity. The
//! mechanism is deliberately simple and sound:
//!
//! * Each action reveals only a `nullifier_hash = Poseidon(secret, epoch)`.
//!   Nobody can link it to a member without the member's `secret`.
//! * To disclose to auditor A, the member seals their `secret` to A's viewing
//!   (X25519) public key ([`seal_disclosure`]). Only A can open it
//!   ([`open_disclosure`]).
//! * A then verifies, for any epoch, that a given on-chain `nullifier_hash` was
//!   produced by that `secret` ([`verify_disclosure`]) — and, via the member's
//!   separate identity attestation over their commitment, attributes it.
//!
//! Disclosure is per-member and per-auditor: one member revealing to one
//! auditor tells that auditor nothing about any other member. There is no master
//! key and no way for the auditor to enumerate non-disclosing members.
//!
//! The sealing scheme is ECIES over X25519 + ChaCha20-Poly1305: the ciphertext
//! is `ephemeral_pubkey(32) || nonce(12) || AEAD(secret)`.

use crate::field::fr_to_bytes_be;
use crate::poseidon;
use crate::Bytes32;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// An auditor's long-lived viewing keypair.
pub struct ViewingKeypair {
    secret: StaticSecret,
    /// The public viewing key a member seals disclosures to.
    pub public: PublicKey,
}

impl ViewingKeypair {
    /// Generate a fresh viewing keypair from the given RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The 32-byte public viewing key a member seals disclosures to.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// The 32-byte secret scalar (persist this to reuse the keypair).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Reconstruct a viewing keypair from a persisted secret.
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Errors from the disclosure path.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComplianceError {
    /// The sealed blob was the wrong length or otherwise unparseable.
    #[error("disclosure ciphertext is malformed")]
    MalformedCiphertext,
    /// AEAD decryption/authentication failed (wrong viewing key or tampered).
    #[error("disclosure could not be decrypted with this viewing key")]
    DecryptionFailed,
    /// The disclosed secret does not reproduce the on-chain nullifier.
    #[error("the disclosed secret does not produce the on-chain nullifier")]
    NullifierMismatch,
}

const EPH_LEN: usize = 32;
const NONCE_LEN: usize = 12;

fn derive_key(shared: &[u8; 32]) -> chacha20poly1305::Key {
    // Domain-separated KDF over the X25519 shared secret.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"mirror-pool/viewing-key/v1");
    h.update(shared);
    let digest = h.finalize();
    chacha20poly1305::Key::clone_from_slice(&digest)
}

/// Seal a member's `secret` to an auditor's viewing public key.
///
/// Output layout: `ephemeral_pubkey(32) || nonce(12) || ciphertext`.
pub fn seal_disclosure<R: RngCore + CryptoRng>(
    secret: Fr,
    auditor_public: &[u8; 32],
    rng: &mut R,
) -> Vec<u8> {
    let ephemeral = StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let auditor_pub = PublicKey::from(*auditor_public);
    let shared = ephemeral.diffie_hellman(&auditor_pub);
    let key = derive_key(shared.as_bytes());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&key);
    // Encryption of a fixed 32-byte plaintext is infallible in practice.
    let ct = cipher
        .encrypt(nonce, fr_to_bytes_be(&secret).as_slice())
        .unwrap_or_default();

    let mut out = Vec::with_capacity(EPH_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Open a sealed disclosure with the auditor's viewing keypair, recovering the
/// member's `secret`.
pub fn open_disclosure(blob: &[u8], auditor: &ViewingKeypair) -> Result<Fr, ComplianceError> {
    if blob.len() < EPH_LEN + NONCE_LEN {
        return Err(ComplianceError::MalformedCiphertext);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&blob[..EPH_LEN]);
    let ephemeral_pub = PublicKey::from(eph);
    let nonce = Nonce::from_slice(&blob[EPH_LEN..EPH_LEN + NONCE_LEN]);
    let ct = &blob[EPH_LEN + NONCE_LEN..];

    let shared = auditor.secret.diffie_hellman(&ephemeral_pub);
    let key = derive_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(&key);
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| ComplianceError::DecryptionFailed)?;
    if pt.len() != 32 {
        return Err(ComplianceError::MalformedCiphertext);
    }
    Ok(Fr::from_be_bytes_mod_order(&pt))
}

/// Verify that a disclosed `secret` produced the on-chain `nullifier_hash` in
/// `epoch`. This is what an auditor runs to attribute an action.
pub fn verify_disclosure(
    secret: Fr,
    epoch: u64,
    nullifier_hash: &Bytes32,
) -> Result<(), ComplianceError> {
    let expected = fr_to_bytes_be(&poseidon::nullifier_hash(secret, Fr::from(epoch)));
    if &expected == nullifier_hash {
        Ok(())
    } else {
        Err(ComplianceError::NullifierMismatch)
    }
}

/// The member's commitment for a disclosed secret (`Poseidon(secret)`), which a
/// separate identity attestation binds to a real-world identity.
pub fn disclosed_commitment(secret: Fr) -> Bytes32 {
    fr_to_bytes_be(&poseidon::commitment(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    // Bridge ark_std's rng (rand 0.8) to rand_core 0.6 used by the dalek crates.
    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xD15C)
    }

    #[test]
    fn disclosure_roundtrip_and_verify() {
        let mut r = rng();
        let auditor = ViewingKeypair::generate(&mut r);
        let secret = Fr::from(0x1234_5678u64);

        let blob = seal_disclosure(secret, &auditor.public_bytes(), &mut r);
        let recovered = open_disclosure(&blob, &auditor).unwrap();
        assert_eq!(recovered, secret);

        // The auditor can attribute the member's on-chain nullifier for any epoch.
        let epoch = 7u64;
        let nh = fr_to_bytes_be(&poseidon::nullifier_hash(secret, Fr::from(epoch)));
        verify_disclosure(recovered, epoch, &nh).unwrap();
    }

    #[test]
    fn other_auditor_cannot_open() {
        let mut r = rng();
        let auditor = ViewingKeypair::generate(&mut r);
        let stranger = ViewingKeypair::generate(&mut r);
        let blob = seal_disclosure(Fr::from(42u64), &auditor.public_bytes(), &mut r);
        assert_eq!(
            open_disclosure(&blob, &stranger).unwrap_err(),
            ComplianceError::DecryptionFailed
        );
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let nh = fr_to_bytes_be(&poseidon::nullifier_hash(Fr::from(1u64), Fr::from(3u64)));
        assert_eq!(
            verify_disclosure(Fr::from(2u64), 3, &nh).unwrap_err(),
            ComplianceError::NullifierMismatch
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut r = rng();
        let auditor = ViewingKeypair::generate(&mut r);
        let mut blob = seal_disclosure(Fr::from(99u64), &auditor.public_bytes(), &mut r);
        let n = blob.len();
        blob[n - 1] ^= 0x01;
        assert!(open_disclosure(&blob, &auditor).is_err());
    }
}
