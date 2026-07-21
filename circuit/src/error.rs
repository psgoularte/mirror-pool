//! Circuit/prover error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("groth16 setup failed: {0}")]
    Setup(String),

    #[error("proof generation failed: {0}")]
    Prove(String),

    #[error("proof verification returned an error: {0}")]
    Verify(String),

    #[error("the generated proof did not verify against the public inputs")]
    ProofRejected,

    #[error("witness construction failed: {0}")]
    Witness(#[from] mirror_pool_common::CommonError),

    #[error("(de)serialization failed: {0}")]
    Serialize(String),
}

pub type Result<T> = core::result::Result<T, CircuitError>;
