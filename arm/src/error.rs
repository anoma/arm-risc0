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
    #[error("Invalid resource index")]
    InvalidResourceIndex,
    #[error("Invalid mcv")]
    InvalidMcv,
}
