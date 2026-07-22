//! Circuit/prover error type.

use thiserror::Error;

/// Errors from the circuit / prover pipeline.
#[derive(Debug, Error)]
pub enum CircuitError {
    /// The Groth16 trusted setup failed.
    #[error("groth16 setup failed: {0}")]
    Setup(String),

    /// Proof generation failed.
    #[error("proof generation failed: {0}")]
    Prove(String),

    /// The verifier returned an error (not merely a `false` result).
    #[error("proof verification returned an error: {0}")]
    Verify(String),

    /// A freshly-generated proof did not verify against its public inputs.
    #[error("the generated proof did not verify against the public inputs")]
    ProofRejected,

    /// Building the witness (root/nullifier/path) failed.
    #[error("witness construction failed: {0}")]
    Witness(#[from] mirror_pool_common::CommonError),

    /// (De)serialization of a key/proof/VK failed.
    #[error("(de)serialization failed: {0}")]
    Serialize(String),
}

/// Convenience result type for circuit/prover operations.
pub type Result<T> = core::result::Result<T, CircuitError>;
