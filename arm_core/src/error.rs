//! Arm-specific error types.
#![allow(missing_docs)]
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArmError {
    #[error("Invalid resource kind")]
    InvalidResourceKind,
    #[error("Invalid resource serialization")]
    InvalidResourceSerialization,
    #[error("Invalid resource deserialization")]
    InvalidResourceDeserialization,
    #[error("Invalid nullifier key")]
    InvalidNullifierKey,
    #[error("Invalid delta")]
    InvalidDelta,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid signing key")]
    InvalidSigningKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Serialization error")]
    SerializationError,
    #[error("Deserialization error")]
    DeserializationError,
    #[error("Journal decode error")]
    JournalDecodingError,
    #[error("Inner receipt deserialization error")]
    InnerReceiptDeserializationError,
    #[error("Unsupported proof type")]
    UnsupportedProofType,
    #[error("Failed to write witness")]
    WriteWitnessFailed,
    #[error("Failed to build prover environment")]
    BuildProverEnvFailed,
    #[error("Verifying key mismatch")]
    VerifyingKeyMismatch,
    #[error("Tag not found")]
    TagNotFound,
    #[error("Delta proof verification failed")]
    DeltaProofVerificationFailed,
    #[error("Expected delta proof, but found witness")]
    ExpectedDeltaProof,
    #[error("Invalid resource value reference")]
    InvalidResourceValueRef,
    #[error("Invalid leaf")]
    InvalidLeaf,
    #[error("Failed to generate proof with error: {0}")]
    ProveFailed(String),
    #[error("Proof verification failed with return code {0}")]
    ProofVerificationFailed(String),
    #[error("Invalid compliance instance")]
    InvalidComplianceInstance,
    #[error("Delta proof generation failed")]
    DeltaProofGenerationFailed,
    #[error("Invalid Random Commitment Value")]
    InvalidRcv,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Instance serialization failed")]
    InstanceSerializationFailed,
    #[error("Missing field: {0}")]
    MissingField(&'static str),
    #[error("Invalid encryption nonce")]
    InvalidEncryptionNonce,
    #[error("Invalid resource nonce")]
    InvalidResourceNonce,
    #[error("Invalid nullifier commitment")]
    InvalidNullifierCommitment,
    #[error("Nullifier duplication detected")]
    NullifierDuplication,
    #[error("kind_table_commitment mismatch across compliance units")]
    KindTableCommitmentMismatch,
    #[error("kind_table_commitment does not match the loaded global kind table")]
    KindTableGlobalMismatch,
    #[error("global kind table not loaded")]
    KindTableNotLoaded,
    #[error("Empty tree")]
    EmptyTree,
    #[error("Invalid shared secret")]
    InvalidSharedSecret,
    #[error("Tree too large")]
    TreeTooLarge,
    #[error("Invalid delta proof: pls regenerate the proof")]
    InvalidDeltaProof,
    #[error("Failed to load kind table")]
    KindTableLoadFailed,
    #[error("Cannot derive nonces from an empty nullifier set")]
    EmptyNullifiers,
    #[error("Cannot compose transactions with different delta types")]
    IncompatibleDeltaTypes,
    #[error("Cannot compress an empty set of delta witnesses")]
    EmptyDeltaWitnesses,
    #[error("Invalid padding resource")]
    InvalidPaddingResource,
    #[error("Actions are missing (transaction has been aggregated or is otherwise invalid)")]
    MissingActions,
    #[error("Cannot compose a transaction that has already been aggregated")]
    CannotComposeAggregated,
    #[error("Transaction must carry exactly one of `actions` or `aggregation`, not both")]
    AmbiguousTransactionRepresentation,
}
