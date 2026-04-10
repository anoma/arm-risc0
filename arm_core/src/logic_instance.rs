//! Logic instance for ARM resource logic proofs.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};

/// Represents a logic instance with its associated data.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpirableBlob {
    /// The blob data as a vector of u32 words.
    pub blob: Vec<u32>,
    /// The deletion criterion for the blob.
    pub deletion_criterion: u32,
}

/// Inputs required to create a logic verifier.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    /// Converts to a LogicInstance given consumed/created flag and action tree root.
    pub fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
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

impl LogicInstance {
    /// Serializes this instance to journal bytes matching
    /// `risc0_zkvm::serde::to_vec(&self)` byte-for-byte. Hand-rolled because
    /// the on-chain Solana PA does not have risc0-serde available, and borsh
    /// is not byte-equivalent — borsh encodes `bool` as one byte, risc0-serde
    /// as a u32 word. The equivalence is pinned by a regression test in the
    /// `arm` crate.
    pub fn to_journal(&self) -> Result<Vec<u8>, crate::error::ArmError> {
        let mut out = Vec::new();
        for word in self.tag.as_words() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&(self.is_consumed as u32).to_le_bytes());
        for word in self.root.as_words() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        for blobs in [
            &self.app_data.resource_payload,
            &self.app_data.discovery_payload,
            &self.app_data.external_payload,
            &self.app_data.application_payload,
        ] {
            out.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
            for blob in blobs {
                out.extend_from_slice(&(blob.blob.len() as u32).to_le_bytes());
                for word in &blob.blob {
                    out.extend_from_slice(&word.to_le_bytes());
                }
                out.extend_from_slice(&blob.deletion_criterion.to_le_bytes());
            }
        }
        Ok(out)
    }
}
