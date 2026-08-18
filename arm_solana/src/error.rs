//! Solana-specific verification errors.
use thiserror::Error;

/// Errors from Solana on-chain verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SolanaArmError {
    /// Transaction contains a delta witness instead of a finalized proof.
    #[error("Expected delta proof, but found witness")]
    ExpectedDeltaProof,
    /// Delta proof bytes are malformed (wrong length or invalid recovery ID).
    #[error("Invalid delta proof")]
    InvalidDeltaProof,
    /// An action carries a delta point not on the secp256k1 curve.
    #[error("Delta point not on secp256k1 curve")]
    DeltaPointNotOnCurve,
    /// ECDSA recovery from the delta proof signature failed.
    #[error("Delta proof verification failed")]
    DeltaProofVerificationFailed,
    /// Recovered public key does not match the accumulated delta point.
    #[error("Delta mismatch: recovered key does not match accumulated delta")]
    DeltaMismatch,
    /// The transaction carries no aggregation; on-chain verification requires
    /// an aggregated transaction.
    #[error("Transaction has no aggregation")]
    MissingAggregation,
    /// The transaction carries both `actions` and `aggregation`; only the
    /// proof-backed aggregation representation is accepted on-chain.
    #[error("Transaction carries both actions and aggregation")]
    AmbiguousTransaction,
}
