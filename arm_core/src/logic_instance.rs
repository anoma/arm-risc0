//! Logic instance for ARM resource logic proofs.

use risc0_zkp::core::digest::Digest;
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
    /// The action tree root this logic proof is bound to.
    pub action_tree_root: Digest,
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

/// Maximum valid `deletion_criterion` value. The protocol adapter maps 0 →
/// `Immediately` and 1 → `Never`; values above 1 are reserved.
pub const MAX_DELETION_CRITERION: u32 = 1;

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

    /// Returns the first blob whose `deletion_criterion` exceeds
    /// [`MAX_DELETION_CRITERION`], or `None` if all blobs are valid.
    pub fn first_invalid_blob(&self) -> Option<&ExpirableBlob> {
        [
            &self.resource_payload,
            &self.discovery_payload,
            &self.external_payload,
            &self.application_payload,
        ]
        .into_iter()
        .flatten()
        .find(|b| b.deletion_criterion > MAX_DELETION_CRITERION)
    }

    /// Appends this value's risc0-serde word encoding to `words`: the four
    /// payload vectors in field order, each length-prefixed.
    pub(crate) fn encode_journal(&self, words: &mut Vec<u32>) {
        for payloads in [
            &self.resource_payload,
            &self.discovery_payload,
            &self.external_payload,
            &self.application_payload,
        ] {
            words.push(payloads.len() as u32);
            for blob in payloads {
                blob.encode_journal(words);
            }
        }
    }
}

impl ExpirableBlob {
    /// Appends this blob's risc0-serde word encoding to `words`:
    /// `blob` as a length-prefixed word sequence, then `deletion_criterion`.
    pub(crate) fn encode_journal(&self, words: &mut Vec<u32>) {
        words.push(self.blob.len() as u32);
        words.extend_from_slice(&self.blob);
        words.push(self.deletion_criterion);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(deletion_criterion: u32) -> ExpirableBlob {
        ExpirableBlob {
            blob: vec![],
            deletion_criterion,
        }
    }

    #[test]
    fn valid_deletion_criteria_are_accepted() {
        for dc in [0, 1] {
            let mut app_data = AppData::new();
            app_data.add_resource_payload(blob(dc));
            assert!(
                app_data.first_invalid_blob().is_none(),
                "deletion_criterion {dc} should be valid"
            );
        }
    }

    #[test]
    fn invalid_deletion_criteria_are_rejected() {
        for dc in [2, 7, u32::MAX] {
            let mut app_data = AppData::new();
            app_data.add_resource_payload(blob(dc));
            let invalid = app_data.first_invalid_blob();
            assert!(
                invalid.is_some(),
                "deletion_criterion {dc} should be invalid"
            );
            assert_eq!(invalid.unwrap().deletion_criterion, dc);
        }
    }

    #[test]
    fn first_invalid_blob_checks_all_payload_kinds() {
        let valid = blob(0);
        let invalid = blob(7);

        for (field, app_data) in [
            ("resource_payload", {
                let mut a = AppData::new();
                a.add_resource_payload(invalid.clone());
                a
            }),
            ("discovery_payload", {
                let mut a = AppData::new();
                a.add_discovery_payload(invalid.clone());
                a
            }),
            ("external_payload", {
                let mut a = AppData::new();
                a.add_external_payload(invalid.clone());
                a
            }),
            ("application_payload", {
                let mut a = AppData::new();
                a.add_application_payload(invalid.clone());
                a
            }),
        ] {
            assert!(
                app_data.first_invalid_blob().is_some(),
                "{field} with deletion_criterion 7 should be caught"
            );
        }

        // All-valid case: mix of valid blobs across all payload kinds.
        let mut all_valid = AppData::new();
        all_valid.add_resource_payload(valid.clone());
        all_valid.add_discovery_payload(valid.clone());
        all_valid.add_external_payload(valid.clone());
        all_valid.add_application_payload(valid.clone());
        assert!(all_valid.first_invalid_blob().is_none());
    }
}
