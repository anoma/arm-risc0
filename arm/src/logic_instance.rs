//! Logic instance for ARM resource logic proofs.

use crate::Digest;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Represents a logic instance with its associated data.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct LogicInstance {
    /// The logic instance's tag (either commitment or nullifier)
    pub tag: Digest,
    /// Indicates whether the logic instance is for a consumed resource.
    pub is_consumed: bool,
    /// The root digest of the logic instance.
    pub root: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
}

/// Application data contains four different types of payloads.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct AppData {
    /// The resource payload blobs.
    pub resource_payload: Vec<ExpirableBlob>,
    /// The discovery payload blobs.
    pub discovery_payload: Vec<ExpirableBlob>,
    /// The external payload blobs.
    pub external_payload: Vec<ExpirableBlob>,
    /// The application payload blobs.
    pub application_payload: Vec<ExpirableBlob>,
}

/// An expirable blob consists of a blob and a deletion criterion.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    pub blob: Vec<u32>,
    /// The deletion criterion for the blob.
    pub deletion_criterion: u32,
}

/// Inputs required to create a logic verifier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct LogicVerifierInputs {
    /// The tag (either commitment or nullifier) for the logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
    /// The logic proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
    /// The pre-serialized logic instance journal (risc0 serde format).
    /// Used for batch aggregation journal digest computation on Solana.
    pub instance_journal: Vec<u8>,
}

impl LogicInstance {
    /// Serializes the instance to a journal format (zkvm serde).
    /// Used when zkvm is enabled for circuit compatibility.
    #[cfg(feature = "zkvm")]
    pub fn to_journal(&self) -> Result<Vec<u8>, crate::error::ArmError> {
        use crate::utils::words_to_bytes;
        use risc0_zkvm::serde::to_vec;
        Ok(words_to_bytes(
            &to_vec(&self).map_err(|_| crate::error::ArmError::InstanceSerializationFailed)?,
        )
        .to_vec())
    }

    /// Serializes the instance to a journal format (borsh).
    /// Used when solana feature is enabled (without zkvm) for Solana compatibility.
    #[cfg(all(feature = "solana", not(feature = "zkvm")))]
    pub fn to_journal(&self) -> Result<Vec<u8>, crate::error::ArmError> {
        borsh::to_vec(&self).map_err(|_| crate::error::ArmError::InstanceSerializationFailed)
    }
}

impl AppData {
    /// Creates a new, empty AppData.
    pub fn new() -> Self {
        AppData {
            resource_payload: Vec::new(),
            discovery_payload: Vec::new(),
            external_payload: Vec::new(),
            application_payload: Vec::new(),
        }
    }

    /// Adds a resource payload blob with its deletion criterion.
    pub fn add_resource_payload(&mut self, blob: ExpirableBlob) {
        self.resource_payload.push(blob);
    }

    /// Adds a discovery payload blob with its deletion criterion.
    pub fn add_discovery_payload(&mut self, blob: ExpirableBlob) {
        self.discovery_payload.push(blob);
    }

    /// Adds an external payload blob with its deletion criterion.
    pub fn add_external_payload(&mut self, blob: ExpirableBlob) {
        self.external_payload.push(blob);
    }

    /// Adds an application payload blob with its deletion criterion.
    pub fn add_application_payload(&mut self, blob: ExpirableBlob) {
        self.application_payload.push(blob);
    }
}
