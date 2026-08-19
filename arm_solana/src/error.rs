//! Solana-specific verification errors.
use thiserror::Error;

/// Errors from Solana on-chain transaction verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SolanaArmError {
    /// Transaction carries no aggregation; settlement only accepts
    /// aggregated transactions.
    #[error("Transaction has no aggregation proof")]
    MissingAggregation,
    /// Transaction carries both base actions and an aggregation — an
    /// ambiguous representation that must be rejected outright.
    #[error("Transaction carries both actions and aggregation")]
    AmbiguousTransaction,
    /// Transaction contains a delta witness instead of a finalized proof.
    #[error("Expected delta proof, but found witness")]
    ExpectedDeltaProof,
    /// Delta proof is malformed or malleable (high-s).
    #[error("Invalid delta proof")]
    InvalidDeltaProof,
    /// An action's delta point could not be used in curve arithmetic.
    #[error("Delta point not on secp256k1 curve")]
    DeltaPointNotOnCurve,
    /// ECDSA recovery from the delta proof signature failed, or the delta
    /// accumulated to the identity (which has no public key).
    #[error("Delta proof verification failed")]
    DeltaProofVerificationFailed,
    /// Recovered public key does not match the accumulated delta point.
    #[error("Delta mismatch: recovered key does not match accumulated delta")]
    DeltaMismatch,
}
