//! Compliance module containing the compliance instance and witness.

/// Size hard-coded to two resources per unit
const COMPLIANCE_INSTANCE_SIZE: usize = 56;

use crate::{error::ArmError, utils::words_to_bytes};
use hex::FromHex;
use k256::{EncodedPoint, ProjectivePoint, elliptic_curve::sec1::FromEncodedPoint};
use lazy_static::lazy_static;
use risc0_serde::to_vec;
use risc0_zkp::core::digest::Digest;
use serde_with::serde_as;

lazy_static! {
    /// The initial root of the empty commitment tree is the hash of an empty string.
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
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
    /// Converts the delta commitment from affine coordinates to a ProjectivePoint.
    pub fn delta_projective(&self) -> Result<ProjectivePoint, ArmError> {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            words_to_bytes(&self.delta_x).into(),
            words_to_bytes(&self.delta_y).into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }

    /// Retrieves the delta message used for signing.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.consumed_nullifier.as_bytes());
        msg.extend_from_slice(self.created_commitment.as_bytes());
        msg
    }

    /// Serializes the instance to a journal format.
    pub fn to_journal(&self) -> Result<Vec<u8>, ArmError> {
        Ok(
            words_to_bytes(&to_vec(&self).map_err(|_| ArmError::InstanceSerializationFailed)?)
                .to_vec(),
        )
    }
}
