//! Logic instance for ARM resource logic proofs.

use crate::Digest;
use serde::{Deserialize, Serialize};

/// Represents a logic instance with its associated data.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
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
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
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
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    pub blob: Vec<u32>,
    /// The deletion criterion for the blob.
    pub deletion_criterion: u32,
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

#[cfg(feature = "zkvm")]
impl LogicInstance {
    /// Serializes this instance to journal bytes (risc0 serde format).
    pub fn to_journal(&self) -> Result<Vec<u8>, crate::error::ArmError> {
        let words = risc0_zkvm::serde::to_vec(self)
            .map_err(|_| crate::error::ArmError::InstanceSerializationFailed)?;
        Ok(crate::utils::words_to_bytes(&words).to_vec())
    }
}

/// Inputs required to create a logic verifier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct LogicVerifierInputs {
    /// The tag (either commitment or nullifier) for the logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
    /// The logic proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
}

impl LogicVerifierInputs {
    /// Converts the LogicVerifierInputs into a LogicInstance.
    pub fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
    }
}

#[cfg(feature = "zkvm")]
impl LogicVerifierInputs {
    /// Retrieves the inner receipt from the logic proof.
    pub fn get_inner_receipt(&self) -> Result<risc0_zkvm::InnerReceipt, crate::error::ArmError> {
        let inner: risc0_zkvm::InnerReceipt = bincode::deserialize(
            self.proof
                .as_ref()
                .ok_or(crate::error::ArmError::MissingField("Missing logic proof"))?,
        )
        .map_err(|_| crate::error::ArmError::InnerReceiptDeserializationError)?;
        Ok(inner)
    }
}
