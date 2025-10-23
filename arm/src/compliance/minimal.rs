// Size hard-coded to two resources per unit
const COMPLIANCE_INSTANCE_SIZE: usize = 56;

use crate::{
    compliance::{
        shared_constraints, ComplianceCircuit, ConsumedMemorandum, CreatedMemorandum, CI,
        INITIAL_ROOT,
    },
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::bytes_to_words,
};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar,
};
use risc0_zkvm::Digest;
use serde_with::serde_as;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    pub consumed_nullifier: Digest,
    pub consumed_logic_ref: Digest,
    pub consumed_commitment_tree_root: Digest,
    pub created_commitment: Digest,
    pub created_logic_ref: Digest,
    // Use u32 array to avoid padding issues in risc0
    pub delta_x: [u32; 8],
    pub delta_y: [u32; 8],
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstanceWords {
    #[serde_as(as = "[_; COMPLIANCE_INSTANCE_SIZE]")]
    pub u32_words: [u32; COMPLIANCE_INSTANCE_SIZE],
}

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
    pub fn from_resources(
        consumed_resource: Resource,
        latest_root: Digest,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        let mut rng = rand::thread_rng();
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::empty(),
            rcv: Scalar::random(&mut rng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: latest_root,
        }
    }

    pub fn from_resources_with_path(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        merkle_path: MerklePath,
        created_resource: Resource,
    ) -> Self {
        let mut rng = rand::thread_rng();
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path,
            rcv: Scalar::random(&mut rng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: *INITIAL_ROOT,
        }
    }

    // Only for tests
    pub fn with_fixed_rcv(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::default(),
            rcv: Scalar::ONE.to_bytes().to_vec(),
            nf_key,
            ephemeral_root: *INITIAL_ROOT,
        }
    }
}

impl CI for ComplianceInstance {
    fn consumed_info(&self) -> Vec<ConsumedMemorandum> {
        vec![ConsumedMemorandum {
            resource_nullifier: self.consumed_nullifier,
            resource_logic_ref: self.consumed_logic_ref,
            commitment_tree_root: self.consumed_commitment_tree_root,
        }]
    }

    fn created_info(&self) -> Vec<CreatedMemorandum> {
        vec![CreatedMemorandum {
            resource_commitment: self.created_commitment,
            resource_logic_ref: self.created_logic_ref,
        }]
    }

    fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        super::to_delta_projective(self.delta_x, self.delta_y)
    }
}

impl ComplianceCircuit for ComplianceWitness {
    type Instance = ComplianceInstance;

    fn constrain(&self) -> Result<Self::Instance, ArmError> {
        // constrain the consumed resource
        let consumed_cm = shared_constraints::commit(&self.consumed_resource);
        let consumed_commitment_tree_root = shared_constraints::compute_commitment_tree_root(
            &consumed_cm,
            &self.merkle_path,
            self.consumed_resource.is_ephemeral,
            &self.ephemeral_root,
        );
        let consumed_logic_ref = shared_constraints::read_resource_logic(&self.consumed_resource);
        let consumed_nullifier = shared_constraints::compute_nullifier(
            &self.consumed_resource,
            &consumed_cm,
            &self.nf_key,
        )?;

        // constrain the created resource
        let created_logic_ref = shared_constraints::read_resource_logic(&self.created_resource);
        let created_commitment = shared_constraints::commit(&self.created_resource);
        constraints::enforce_correct_nonce(&self.created_resource, consumed_nullifier)?;

        // compute unit delta
        let (delta_x, delta_y) =
            constraints::delta_commit(&self.consumed_resource, &self.created_resource, &self.rcv)?;

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
}

impl Default for ComplianceWitness {
    // The default value is meaningless and only for testing
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

/// Constraints specific to 2-size compliance units.
mod constraints {
    use super::*;

    /// Constrain the nonce of the created resource
    pub(super) fn enforce_correct_nonce(
        created_resource: &Resource,
        consumed_nullifier: Digest,
    ) -> Result<(), ArmError> {
        if created_resource.nonce != consumed_nullifier.as_bytes() {
            Err(ArmError::InvalidResourceNonce)
        } else {
            Ok(())
        }
    }

    /// Computes the Delta commitment of the 2-sized compliance unit.
    pub(super) fn delta_commit(
        consumed_resource: &Resource,
        created_resource: &Resource,
        rcv: &[u8],
    ) -> Result<([u32; 8], [u32; 8]), ArmError> {
        let rcv_array: [u8; 32] = rcv.try_into().map_err(|_| ArmError::InvalidRcv)?;
        let rcv_scalar = Scalar::from_repr(rcv_array.into())
            .into_option()
            .ok_or(ArmError::InvalidRcv)?;
        let consumed_kind = consumed_resource.kind()?;
        let created_kind = created_resource.kind()?;
        let delta = consumed_kind * consumed_resource.quantity_scalar()
            - created_kind * created_resource.quantity_scalar()
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
