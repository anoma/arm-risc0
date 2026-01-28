//! Compliance module containing the compliance instance and witness.

/// Size hard-coded to two resources per unit
const COMPLIANCE_INSTANCE_SIZE: usize = 56;

use crate::{
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, words_to_bytes},
};
use hex::FromHex;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use risc0_zkvm::Digest;
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

/// The compliance witness contains all private inputs to the compliance proof.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness {
    /// The consumed resource
    pub consumed_resource: Resource,
    /// The path from the consumed commitment to the root in the commitment tree
    pub merkle_path: MerklePath,
    /// The existing root for the ephemeral resource
    pub ephemeral_root: Digest,
    /// Nullifier key of the consumed resource
    pub nf_key: NullifierKey,
    /// The created resource
    pub created_resource: Resource,
    /// Random scalar for delta commitment
    pub rcv: Vec<u8>,
    // TODO: If we want to add function privacy, include:
    // pub input_resource_logic_cm_r: [u8; DATA_BYTES],
    // pub output_resource_logic_cm_r: [u8; DATA_BYTES],
}

impl ComplianceWitness {
    /// Creates a new compliance witness from the given resources and latest
    /// root when consuming an ephemeral resource.
    pub fn from_resources(
        consumed_resource: Resource,
        latest_root: Digest,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::empty(),
            rcv: Scalar::random(&mut OsRng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: latest_root,
        }
    }

    /// Creates a new compliance witness from the given resources and merkle
    /// path when consuming a non-ephemeral resource.
    pub fn from_resources_with_path(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        merkle_path: MerklePath,
        created_resource: Resource,
    ) -> Self {
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path,
            rcv: Scalar::random(&mut OsRng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: *INITIAL_ROOT,
        }
    }

    /// Compliance constraints
    pub fn constrain(&self) -> Result<ComplianceInstance, ArmError> {
        let consumed_cm = self.consumed_commitment();
        let consumed_logic_ref = self.consumed_resource_logic();
        let consumed_commitment_tree_root = self.consumed_commitment_tree_root(&consumed_cm);

        let consumed_nullifier = self.consumed_nullifier(&consumed_cm)?;
        let created_logic_ref = self.created_resource_logic();
        let created_commitment = self.created_commitment();

        // constrain created_resource.nonce and consumed_resource.nf
        assert_eq!(
            self.created_resource.nonce,
            consumed_nullifier.as_bytes(),
            "Created resource nonce must match consumed nullifier"
        );

        let (delta_x, delta_y) = self.delta()?;

        Ok(ComplianceInstance {
            consumed_nullifier,
            consumed_logic_ref,
            consumed_commitment_tree_root,
            created_commitment,
            created_logic_ref,
            delta_x,
            delta_y,
        })
    }

    /// Get the logic ref of consumed resource
    pub fn consumed_resource_logic(&self) -> Digest {
        self.consumed_resource.logic_ref
    }

    /// Get the logic ref of created resource
    pub fn created_resource_logic(&self) -> Digest {
        self.created_resource.logic_ref
    }

    /// Compute the commitment of created resource
    pub fn consumed_commitment(&self) -> Digest {
        self.consumed_resource.commitment()
    }

    /// Compute the commitment of created resource
    pub fn created_commitment(&self) -> Digest {
        self.created_resource.commitment()
    }

    /// Compute the nullifier of consumed resource
    pub fn consumed_nullifier(&self, cm: &Digest) -> Result<Digest, ArmError> {
        self.consumed_resource
            .nullifier_from_commitment(&self.nf_key, cm)
    }

    /// Compute the commitment tree root for consumed resource
    pub fn consumed_commitment_tree_root(&self, cm: &Digest) -> Digest {
        if self.consumed_resource.is_ephemeral {
            self.ephemeral_root
        } else {
            self.merkle_path.root(cm)
        }
    }

    /// Compute the delta commitment
    pub fn delta(&self) -> Result<([u32; 8], [u32; 8]), ArmError> {
        // Compute delta and make delta commitment public
        let rcv_array: [u8; 32] = self
            .rcv
            .as_slice()
            .try_into()
            .map_err(|_| ArmError::InvalidRcv)?;
        let rcv_scalar = Scalar::from_repr(rcv_array.into())
            .into_option()
            .ok_or(ArmError::InvalidRcv)?;
        let consumed_kind = self.consumed_resource.kind()?;
        let created_kind = self.created_resource.kind()?;
        let delta = created_kind * self.created_resource.quantity_scalar()
            - consumed_kind * self.consumed_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * rcv_scalar;

        let encoded_delta = delta.to_encoded_point(false);
        let delta_x: [u32; 8] = bytes_to_words(encoded_delta.x().ok_or(ArmError::InvalidDelta)?)
            .try_into()
            .map_err(|_| ArmError::InvalidDelta)?;

        let delta_y: [u32; 8] = bytes_to_words(encoded_delta.y().ok_or(ArmError::InvalidDelta)?)
            .try_into()
            .map_err(|_| ArmError::InvalidDelta)?;

        Ok((delta_x, delta_y))
    }
}

impl Default for ComplianceWitness {
    fn default() -> Self {
        let nf_key = NullifierKey::default();

        let consumed_resource = Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: [0u8; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: [0u8; 32],
        };

        let nf = consumed_resource.nullifier(&nf_key).unwrap();

        let created_resource = Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: nf.as_bytes().try_into().unwrap(),
            nk_commitment: nf_key.commit(),
            rand_seed: [0u8; 32],
        };

        let merkle_path = MerklePath::default();

        let rcv = Scalar::ONE.to_bytes().to_vec();

        ComplianceWitness {
            consumed_resource,
            created_resource,
            ephemeral_root: *INITIAL_ROOT,
            merkle_path,
            rcv,
            nf_key,
        }
    }
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
