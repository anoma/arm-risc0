//! Arm-specific error types.
#![allow(missing_docs)]
use risc0_zkp::core::digest::Digest;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArmError {
    #[error("Invalid resource kind")]
    InvalidResourceKind,
    #[error("{found} kind paths, the compliance witness has {expected} resources")]
    KindPathCountMismatch { expected: usize, found: usize },
    #[error("kind base at position {position} is not an uncompressed SEC1 point (65 bytes, leading 0x04)")]
    InvalidKindBaseEncoding { position: usize },
    #[error("kind base at position {position} is not a point on secp256k1")]
    KindBaseNotOnCurve { position: usize },
    #[error(
        "kind path {position} opens under root {found}, an earlier path opened under {expected}"
    )]
    KindPathRootMismatch {
        position: usize,
        expected: Digest,
        found: Digest,
    },
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
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Deserialization failed")]
    DeserializationFailed,
    #[error("Journal decoding failed")]
    JournalDecodingFailed,
    #[error("Inner receipt deserialization failed")]
    InnerReceiptDeserializationFailed,
    #[error("Unsupported proof type")]
    UnsupportedProofType,
    #[error("Failed to write witness")]
    WriteWitnessFailed,
    #[error("Failed to build prover environment")]
    BuildProverEnvFailed,
    #[error("Verifying key mismatch")]
    VerifyingKeyMismatch,
    #[error("{found} logic verifier inputs, the compliance instance expects {expected}")]
    LogicVerifierInputCountMismatch { expected: usize, found: usize },
    #[error("logic verifier input {position} has tag {found}, the compliance instance expects tag {expected}")]
    LogicVerifierTagMismatch {
        position: usize,
        expected: Digest,
        found: Digest,
    },
    /// Locates an error at the action it came from; `source` is the condition.
    #[error("action {action}: {source}")]
    InAction {
        action: usize,
        source: Box<ArmError>,
    },
    #[error("Delta proof verification failed")]
    DeltaProofVerificationFailed,
    #[error("Expected delta proof, but found witness")]
    ExpectedDeltaProof,
    #[error("Invalid resource value reference")]
    InvalidResourceValueRef,
    #[error("Invalid leaf")]
    InvalidLeaf,
    #[error("leaf {leaf} is not in the action tree")]
    LeafNotInActionTree { leaf: Digest },
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
    #[error("kind_tree_root mismatch across actions")]
    KindTreeRootMismatch,
    #[error("kind_tree_root does not match the expected root")]
    KindTreeRootExpectedMismatch,
    #[error("Empty tree")]
    EmptyTree,
    #[error("Invalid shared secret")]
    InvalidSharedSecret,
    #[error("Tree too large")]
    TreeTooLarge,
    #[error("Invalid delta proof: pls regenerate the proof")]
    InvalidDeltaProof,
    #[error("Failed to load kind tree")]
    KindTreeLoadFailed,
    #[error("kind tree has two entries for (logic_ref {logic_ref}, label_ref {label_ref})")]
    DuplicateKindTreeEntry {
        logic_ref: Digest,
        label_ref: Digest,
    },
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
    #[error("transaction has no actions")]
    EmptyActions,
    #[error("transaction has already been aggregated")]
    AlreadyAggregated,
    #[error("Transaction carries no aggregation proof")]
    MissingAggregation,
    #[error("Cannot compose a transaction that has already been aggregated")]
    CannotComposeAggregated,
    #[error("Transaction must carry exactly one of `actions` or `aggregation`, not both")]
    AmbiguousTransactionRepresentation,
}
