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

impl From<&ComplianceInstance> for ComplianceInstanceWords {
    fn from(instance: &ComplianceInstance) -> Self {
        let mut words = [0u32; COMPLIANCE_INSTANCE_SIZE];
        words[0..8].copy_from_slice(instance.consumed_nullifier.as_words());
        words[8..16].copy_from_slice(instance.consumed_logic_ref.as_words());
        words[16..24].copy_from_slice(instance.consumed_commitment_tree_root.as_words());
        words[24..32].copy_from_slice(instance.created_commitment.as_words());
        words[32..40].copy_from_slice(instance.created_logic_ref.as_words());
        words[40..48].copy_from_slice(&instance.delta_x);
        words[48..56].copy_from_slice(&instance.delta_y);
        ComplianceInstanceWords { u32_words: words }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_instance_to_words_roundtrip() {
        let instance = ComplianceInstance {
            consumed_nullifier: Digest::new([1, 2, 3, 4, 5, 6, 7, 8]),
            consumed_logic_ref: Digest::new([9, 10, 11, 12, 13, 14, 15, 16]),
            consumed_commitment_tree_root: Digest::new([17, 18, 19, 20, 21, 22, 23, 24]),
            created_commitment: Digest::new([25, 26, 27, 28, 29, 30, 31, 32]),
            created_logic_ref: Digest::new([33, 34, 35, 36, 37, 38, 39, 40]),
            delta_x: [41, 42, 43, 44, 45, 46, 47, 48],
            delta_y: [49, 50, 51, 52, 53, 54, 55, 56],
        };

        let words: ComplianceInstanceWords = (&instance).into();

        // Each field occupies 8 words in order
        assert_eq!(
            &words.u32_words[0..8],
            instance.consumed_nullifier.as_words()
        );
        assert_eq!(
            &words.u32_words[8..16],
            instance.consumed_logic_ref.as_words()
        );
        assert_eq!(
            &words.u32_words[16..24],
            instance.consumed_commitment_tree_root.as_words()
        );
        assert_eq!(
            &words.u32_words[24..32],
            instance.created_commitment.as_words()
        );
        assert_eq!(
            &words.u32_words[32..40],
            instance.created_logic_ref.as_words()
        );
        assert_eq!(&words.u32_words[40..48], &instance.delta_x);
        assert_eq!(&words.u32_words[48..56], &instance.delta_y);
    }

    #[test]
    fn compliance_instance_to_words_default_is_all_zeros() {
        let instance = ComplianceInstance::default();
        let words: ComplianceInstanceWords = (&instance).into();
        assert_eq!(words.u32_words, [0u32; 56]);
    }
}
