use crate::{
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::{ConsumedDatum, ConsumedMemorandum, CreatedMemorandum, Resource},
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
use risc0_zkvm::Digest;

lazy_static! {
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceInstance {
    /// Public information of consumed resources
    pub consumed_memorandums: Vec<ConsumedMemorandum>,
    /// Public information of created resources
    pub created_memorandums: Vec<CreatedMemorandum>,
    // Delta commitment of the compliance unit. (Use u32 array to avoid padding issues in risc0)
    pub delta_x: [u32; 8],
    pub delta_y: [u32; 8],
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness {
    /// Required consumed information
    pub consumed_data: Vec<ConsumedDatum>,
    /// Required created information
    pub created_resources: Vec<Resource>,
    /// The existing root for ephemeral resources
    pub ephemeral_root: Digest,
    /// Bytes of randommness for the delta commitments `rcv`
    pub rcv: Vec<u8>,
}

impl ComplianceWitness {
    pub fn from_resources_info(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
    ) -> Self {
        Self::from_resources_info_with_eph_root(consumed_data, created_resources, *INITIAL_ROOT)
    }

    pub fn from_resources_info_with_eph_root(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
        latest_root: Digest,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let rcv = Scalar::random(&mut rng).to_bytes();

        Self::from_all_data(
            consumed_data,
            created_resources,
            latest_root,
            rcv.as_slice(),
        )
    }

    fn from_all_data(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
        ephemeral_root: Digest,
        rcv: &[u8],
    ) -> ComplianceWitness {
        ComplianceWitness {
            consumed_data: consumed_data.to_vec(),
            created_resources: created_resources.to_vec(),
            ephemeral_root,
            rcv: rcv.to_vec(),
        }
    }

    pub fn constrain(&self) -> Result<ComplianceInstance, ArmError> {
        let (consumed_memorandums, created_memorandums) = constraints::constrain_resources(
            &self.consumed_data,
            &self.created_resources,
            self.ephemeral_root,
        )?;

        let consumed_resources: Vec<Resource> = self
            .consumed_data
            .iter()
            .map(|datum| datum.resource)
            .collect();
        let (delta_x, delta_y) =
            constraints::delta_commit(&consumed_resources, &self.created_resources, &self.rcv)?;

        Ok(ComplianceInstance {
            consumed_memorandums,
            created_memorandums,
            delta_x,
            delta_y,
        })
    }
}

impl Default for ComplianceWitness {
    /// The default value is meaningless and only for testing.
    /// It contains three consumed and two created resources.
    fn default() -> Self {
        let consumed_data = vec![ConsumedDatum::default(); 3];

        let consumed_nullifiers = vec![
            consumed_data[0]
                .resource
                .nullifier(&consumed_data[0].nf_key)
                .unwrap(),
            consumed_data[1]
                .resource
                .nullifier(&consumed_data[1].nf_key)
                .unwrap(),
            consumed_data[2]
                .resource
                .nullifier(&consumed_data[1].nf_key)
                .unwrap(),
        ];

        let nonce_0 = Resource::derive_nonce_from_nullifiers(0, &consumed_nullifiers).unwrap();
        let nonce_1 = Resource::derive_nonce_from_nullifiers(1, &consumed_nullifiers).unwrap();

        let consumed_resource_0 = Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: nonce_0,
            nk_commitment: NullifierKey::default().commit(),
            rand_seed: [0u8; 32],
        };

        let consumed_resource_1 = Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: nonce_1,
            nk_commitment: NullifierKey::default().commit(),
            rand_seed: [0u8; 32],
        };

        ComplianceWitness {
            consumed_data,
            created_resources: vec![consumed_resource_0, consumed_resource_1],
            ephemeral_root: *INITIAL_ROOT,
            rcv: Scalar::ONE.to_bytes().to_vec(),
        }
    }
}

impl ComplianceInstance {
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

    /// Returns the contribution of this compliance instance to the delta message.
    /// Namely, the list of tags as bytes.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for tag in self
            .consumed_memorandums
            .iter()
            .map(|memo| memo.resource_nullifier)
            .chain(
                self.created_memorandums
                    .iter()
                    .map(|memo| memo.resource_commitment),
            )
        {
            msg.extend_from_slice(tag.as_bytes());
        }
        msg
    }
}

/// This module self-contains all enforced constraints.
mod constraints {
    use super::*;

    /// Consumption and creation constraints. The unit's Delta is NOT constrained here.
    pub(super) fn constrain_resources(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
        ephemeral_root: Digest,
    ) -> Result<(Vec<ConsumedMemorandum>, Vec<CreatedMemorandum>), ArmError> {
        let mut consumed_nullifiers = Vec::with_capacity(consumed_data.len());

        // Constrain consumed resources.
        let mut consumed_memo = Vec::with_capacity(consumed_data.len());
        for consumed_datum in consumed_data.iter() {
            let resource_commitment = constraints::commit(&consumed_datum.resource);
            let commitment_tree_root = constraints::compute_commitment_tree_root(
                &resource_commitment,
                &consumed_datum.merkle_path,
                consumed_datum.resource.is_ephemeral,
                &ephemeral_root,
            );
            let resource_nullifier = constraints::compute_nullifier(
                &consumed_datum.resource,
                &resource_commitment,
                &consumed_datum.nf_key,
            )?;
            let resource_logic_ref = constraints::read_resource_logic(&consumed_datum.resource);

            consumed_memo.push(ConsumedMemorandum {
                resource_nullifier,
                resource_logic_ref,
                commitment_tree_root,
            });
            consumed_nullifiers.push(resource_nullifier);
        }

        // Constrain created resources.
        let mut created_memo = Vec::with_capacity(created_resources.len());
        let consumed_nullifiers_digest =
            constraints::hash_consumed_nullifiers(&consumed_nullifiers)?;
        for (index, resource) in created_resources.iter().enumerate() {
            created_memo.push(CreatedMemorandum {
                resource_commitment: constraints::commit(resource),
                resource_logic_ref: constraints::read_resource_logic(resource),
            });
            constraints::enforce_correct_nonce(resource, index, consumed_nullifiers_digest)?;
        }

        // All good.
        Ok((consumed_memo, created_memo))
    }

    /// Constrains the Delta commitment of the unit.
    pub(super) fn delta_commit(
        consumed_resources: &[Resource],
        created_resources: &[Resource],
        rcv: &[u8],
    ) -> Result<([u32; 8], [u32; 8]), ArmError> {
        let rcv_array: [u8; 32] = rcv.try_into().map_err(|_| ArmError::InvalidRcv)?;
        let rcv_scalar = Scalar::from_repr(rcv_array.into())
            .into_option()
            .ok_or(ArmError::InvalidRcv)?;

        // First, sum signed quantities of the same kind to minimize scalar multiplications.
        let capacity = consumed_resources.len() + created_resources.len();
        let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(capacity);
        let mut sums: Vec<Scalar> = Vec::with_capacity(capacity);
        for (resource, is_consumed) in consumed_resources
            .iter()
            .map(|resource| (resource, true))
            .chain(created_resources.iter().map(|resource| (resource, false)))
        {
            let kind = resource.kind()?;
            let signed_quantity = if is_consumed {
                resource.quantity_scalar()
            } else {
                -resource.quantity_scalar()
            };
            if let Some(index) = kinds.iter().position(|stored_kind| *stored_kind == kind) {
                sums[index] += signed_quantity;
            } else {
                kinds.push(kind);
                sums.push(signed_quantity);
            }
        }

        // Pedersen commit to all sums. The binding generators are the different kind points.
        let delta = kinds
            .iter()
            .zip(sums.iter())
            .fold(ProjectivePoint::IDENTITY, |acc, kind_sum| {
                acc + kind_sum.0 * kind_sum.1
            })
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

    fn commit(resource: &Resource) -> Digest {
        resource.commitment()
    }
    fn compute_commitment_tree_root(
        resource_commitment: &Digest,
        merkle_path: &MerklePath,
        resource_is_ephemeral: bool,
        ephemeral_root: &Digest,
    ) -> Digest {
        if resource_is_ephemeral {
            *ephemeral_root
        } else {
            merkle_path.root(resource_commitment)
        }
    }

    /// By returning the logic vk of the resource we force it is loaded from memory onto the computational trace.
    fn read_resource_logic(resource: &Resource) -> Digest {
        resource.logic_ref
    }

    fn compute_nullifier(
        resource: &Resource,
        commitment: &Digest,
        nf_key: &NullifierKey,
    ) -> Result<Digest, ArmError> {
        resource.nullifier_from_commitment(nf_key, commitment)
    }

    // Re-derive the nonce and enforce equality.
    fn enforce_correct_nonce(
        resource: &Resource,
        index: usize,
        consumed_nullifiers_digest: Digest,
    ) -> Result<(), ArmError> {
        let correct_nonce = Resource::derive_nonce(index, consumed_nullifiers_digest)?;
        if correct_nonce != resource.nonce {
            return Err(ArmError::InvalidResourceNonce);
        }

        Ok(())
    }

    /// It fails if the passed nullifiers is an empty vec. In this case,
    /// there is no entropy to ensure uniqueness of created nonces.
    fn hash_consumed_nullifiers(nullifiers: &[Digest]) -> Result<Digest, ArmError> {
        if nullifiers.is_empty() {
            return Err(ArmError::InvalidResourceNonce);
        }
        Ok(Resource::hash_nullifiers(nullifiers))
    }
}
