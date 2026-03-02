//! Compliance module containing the compliance witness.

pub use arm_core::compliance::ComplianceInstanceWords;

use crate::{
    error::ArmError,
    merkle_path::{MerklePath, MerklePathExt},
    nullifier_key::{NullifierKey, NullifierKeyExt},
    resource::Resource,
    utils::{bytes_to_words, words_to_bytes},
    Digest,
};
pub use arm_core::compliance::ComplianceInstance;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use rand::rngs::OsRng;

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
            ephemeral_root: arm_core::compliance::initial_root(),
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
            ephemeral_root: arm_core::compliance::initial_root(),
            merkle_path,
            rcv,
            nf_key,
        }
    }
}

/// Extension methods for ComplianceInstance requiring k256.
pub trait ComplianceInstanceExt {
    /// Converts the delta commitment from affine coordinates to a ProjectivePoint.
    fn delta_projective(&self) -> Result<ProjectivePoint, ArmError>;
}

impl ComplianceInstanceExt for ComplianceInstance {
    fn delta_projective(&self) -> Result<ProjectivePoint, ArmError> {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            words_to_bytes(&self.delta_x).into(),
            words_to_bytes(&self.delta_y).into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }
}

/// Extension methods to serialize compliance instances into risc0 journal bytes.
pub trait ComplianceInstanceJournalExt {
    /// Serialize a compliance instance to the journal byte format.
    fn to_journal(&self) -> Result<Vec<u8>, ArmError>;
}

impl ComplianceInstanceJournalExt for ComplianceInstance {
    fn to_journal(&self) -> Result<Vec<u8>, ArmError> {
        let words =
            risc0_zkvm::serde::to_vec(self).map_err(|_| ArmError::InstanceSerializationFailed)?;
        Ok(arm_core::utils::words_to_bytes(&words).to_vec())
    }
}
