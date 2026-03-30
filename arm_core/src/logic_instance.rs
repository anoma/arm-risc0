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
    /// SHA-256 hash of borsh-serialized app_data. Committed by the logic circuit
    /// and verified on-chain to bind app_data to the ZK proof.
    pub app_data_hash: Digest,
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
    /// Pre-serialized LogicInstance journal bytes from proving.
    pub instance_journal: Vec<u8>,
}

impl LogicVerifierInputs {
    /// Converts to a LogicInstance given consumed/created flag and action tree root.
    /// The `app_data_hash` is set to default; callers that need the hash must call
    /// `compute_and_set_app_data_hash()` on the result.
    pub fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
            app_data_hash: Digest::default(),
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

#[cfg(feature = "borsh")]
impl AppData {
    /// Computes SHA-256 hash of the borsh-serialized AppData.
    pub fn compute_hash(&self) -> Digest {
        use sha2::{Digest as Sha2Digest, Sha256};
        let bytes = borsh::to_vec(self).expect("AppData borsh serialization cannot fail");
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        crate::digest::Digest::from_bytes(hash)
    }
}

#[cfg(feature = "borsh")]
impl LogicInstance {
    /// Sets `app_data_hash` to the SHA-256 hash of borsh-serialized `app_data`.
    /// Must be called before committing in a logic circuit guest.
    pub fn compute_and_set_app_data_hash(&mut self) {
        self.app_data_hash = self.app_data.compute_hash();
    }

    /// Serializes this instance to journal bytes (Borsh format).
    ///
    /// Layout: `borsh(fields_except_hash) | padding_to_4byte | borsh(app_data_hash)`
    ///
    /// The hash is always the last 32 bytes of the output, making extraction
    /// trivial for the on-chain verifier. Padding ensures the hash starts at
    /// a 4-byte aligned offset for risc0's `env::verify` which operates on
    /// `&[u32]` journals.
    pub fn to_journal(&self) -> Result<Vec<u8>, crate::error::ArmError> {
        let err = |_| crate::error::ArmError::InstanceSerializationFailed;

        // Serialize everything except app_data_hash.
        let mut bytes = Vec::new();
        borsh::BorshSerialize::serialize(&self.tag, &mut bytes).map_err(err)?;
        borsh::BorshSerialize::serialize(&self.is_consumed, &mut bytes).map_err(err)?;
        borsh::BorshSerialize::serialize(&self.root, &mut bytes).map_err(err)?;
        borsh::BorshSerialize::serialize(&self.app_data, &mut bytes).map_err(err)?;

        // Pad to 4-byte alignment before the hash.
        let padding = (4 - bytes.len() % 4) % 4;
        bytes.resize(bytes.len() + padding, 0);

        // Append the hash (32 bytes, already 4-byte aligned).
        borsh::BorshSerialize::serialize(&self.app_data_hash, &mut bytes).map_err(err)?;

        Ok(bytes)
    }
}
