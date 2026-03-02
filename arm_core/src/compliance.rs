//! Compliance module containing the compliance instance.

use crate::{constants::EMPTY_HASH_BYTES, digest::Digest, error::ArmError, utils::bytes_to_words};
use serde_with::serde_as;

const COMPLIANCE_INSTANCE_SIZE: usize = 56;

/// Returns the initial root of the empty commitment tree.
pub fn initial_root() -> Digest {
    Digest::try_from(EMPTY_HASH_BYTES.as_slice()).unwrap()
}

/// The compliance instance contains all public inputs to the compliance proof.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComplianceInstance {
    /// The nullifier of the consumed resource.
    pub consumed_nullifier: Digest,
    /// The logic ref of the consumed resource.
    pub consumed_logic_ref: Digest,
    /// The commitment tree root for the consumed resource.
    pub consumed_commitment_tree_root: Digest,
    /// The commitment of the created resource.
    pub created_commitment: Digest,
    /// The logic ref of the created resource.
    pub created_logic_ref: Digest,
    /// The delta x coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_x: [u32; 8],
    /// The delta y coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_y: [u32; 8],
}

/// The compliance instance represented as an array of u32 words for
/// serialization(used in the aggregation circuit).
#[serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstanceWords {
    /// The compliance instance as an array of u32 words.
    #[serde_as(as = "[_; COMPLIANCE_INSTANCE_SIZE]")]
    pub u32_words: [u32; COMPLIANCE_INSTANCE_SIZE],
}

impl ComplianceInstance {
    /// Retrieves the delta message used for signing.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.consumed_nullifier.as_bytes());
        msg.extend_from_slice(self.created_commitment.as_bytes());
        msg
    }
}

impl ComplianceInstanceWords {
    /// Creates a ComplianceInstanceWords from a byte slice.
    pub fn from_bytes(instance_bytes: &[u8]) -> Result<Self, ArmError> {
        let u32_words: [u32; COMPLIANCE_INSTANCE_SIZE] = bytes_to_words(instance_bytes)
            .try_into()
            .map_err(|_| ArmError::InstanceSerializationFailed)?;
        Ok(ComplianceInstanceWords { u32_words })
    }
}
