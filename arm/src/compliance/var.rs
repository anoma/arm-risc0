use crate::{
    compliance::{shared_constraints, ComplianceCircuit, INITIAL_ROOT},
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, words_to_bytes},
};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use risc0_zkvm::sha::{Impl, Sha256};
use risc0_zkvm::Digest;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceVarWitness {
    /// Required consumed information
    pub consumed_data: Vec<ConsumedDatum>,
    /// Required created information
    pub created_resources: Vec<Resource>,
    /// The existing root for ephemeral resources
    pub ephemeral_root: Digest,
    /// Random scalar for delta commitment
    pub rcv: Vec<u8>,
}

/// Private information related to a consumed resource
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsumedDatum {
    /// The consumed resource.
    pub resource: Resource,
    /// The path from the consumed commitment to the root of the commitment tree
    pub merkle_path: MerklePath,
    /// Nullifier key of the consumed resource
    pub nf_key: NullifierKey,
}

impl ComplianceVarWitness {
    // Only for tests
    pub fn with_fixed_rcv(
        consumed_resources: &[Resource],
        nf_keys: &[NullifierKey],
        created_resources: &[Resource],
    ) -> Self {
        assert_eq!(consumed_resources.len(), nf_keys.len());
        ComplianceVarWitness {
            consumed_data: consumed_resources
                .iter()
                .zip(nf_keys)
                .map(|(resource, nf_key)| ConsumedDatum {
                    resource: *resource,
                    merkle_path: MerklePath::default(),
                    nf_key: nf_key.clone(),
                })
                .collect(),
            created_resources: created_resources.to_vec(),
            ephemeral_root: *INITIAL_ROOT,
            rcv: Scalar::ONE.to_bytes().to_vec(),
        }
    }
}

impl ComplianceCircuit for ComplianceVarWitness {
    type Instance = ComplianceVarInstance;

    fn constrain(&self) -> Result<Self::Instance, ArmError> {
        let (consumed_memorandums, created_memorandums) = var_constraints::constrain_resources(
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
            var_constraints::delta_commit(&consumed_resources, &self.created_resources, &self.rcv)?;

        Ok(ComplianceVarInstance {
            consumed_memorandums,
            created_memorandums,
            delta_x,
            delta_y,
        })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceVarInstance {
    /// Public information of consumed resources
    pub consumed_memorandums: Vec<ConsumedMemorandum>,
    /// Public information of created resources
    pub created_memorandums: Vec<CreatedMemorandum>,
    // Delta commitment of the compliance unit. (Use u32 array to avoid padding issues in risc0)
    pub delta_x: [u32; 8],
    pub delta_y: [u32; 8],
}

impl ComplianceVarInstance {
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
}

/// Public information of created resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CreatedMemorandum {
    /// The commitment to the created [Resource]
    pub resource_commitment: Digest,
    /// The logic reference of the created [Resource].
    pub resource_logic_ref: Digest,
}

/// Public information of consumed resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsumedMemorandum {
    /// The nullifier of the consumed [Resource]
    pub resource_nullifier: Digest,
    /// The logic reference of the consumed [Resource]
    pub logic_ref: Digest,
    /// The root of the Merkle tree where the resource commitment is in.
    pub commitment_tree_root: Digest,
}

/// Constraints specific to variable-size compliance units.
pub(crate) mod var_constraints {
    use super::*;

    /// Gathers up consumption and creation constraints. Note the
    /// constraint of the unit's Delta is NOT enforced here.
    pub(crate) fn constrain_resources(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
        ephemeral_root: Digest,
    ) -> Result<(Vec<ConsumedMemorandum>, Vec<CreatedMemorandum>), ArmError> {
        let mut consumed_nullifiers = Vec::with_capacity(consumed_data.len());

        // Constrain consumed resources.
        let mut consumed_memo = Vec::with_capacity(consumed_data.len());
        for consumed_datum in consumed_data.iter() {
            let resource_commitment = shared_constraints::commit(&consumed_datum.resource);
            let commitment_tree_root = shared_constraints::compute_commitment_tree_root(
                &resource_commitment,
                &consumed_datum.merkle_path,
                consumed_datum.resource.is_ephemeral,
                &ephemeral_root,
            );
            let resource_nullifier = shared_constraints::compute_nullifier(
                &consumed_datum.resource,
                &resource_commitment,
                &consumed_datum.nf_key,
            )?;
            let logic_ref = shared_constraints::read_resource_logic(&consumed_datum.resource);

            consumed_memo.push(ConsumedMemorandum {
                resource_nullifier,
                logic_ref,
                commitment_tree_root,
            });
            consumed_nullifiers.push(resource_nullifier);
        }

        // Constrain created resources.
        let mut created_memo = Vec::with_capacity(created_resources.len());
        let consumed_nullifiers_digest =
            var_constraints::hash_consumed_nullifiers(&consumed_nullifiers);
        for (index, resource) in created_resources.iter().enumerate() {
            created_memo.push(CreatedMemorandum {
                resource_commitment: shared_constraints::commit(resource),
                resource_logic_ref: shared_constraints::read_resource_logic(resource),
            });
            var_constraints::enforce_correct_nonce(resource, index, consumed_nullifiers_digest)?;
        }

        // All good.
        Ok((consumed_memo, created_memo))
    }

    /// Computes the Delta commitment of the variable compliance unit.
    pub(super) fn delta_commit(
        consumed_resources: &[Resource],
        created_resources: &[Resource],
        rcv: &[u8],
    ) -> Result<([u32; 8], [u32; 8]), ArmError> {
        let rcv_array: [u8; 32] = rcv.try_into().map_err(|_| ArmError::InvalidRcv)?;
        let rcv_scalar = Scalar::from_repr(rcv_array.into())
            .into_option()
            .ok_or(ArmError::InvalidRcv)?;

        let mut consumed_quantities_bindings = Vec::with_capacity(consumed_resources.len());
        for resource in consumed_resources.iter() {
            consumed_quantities_bindings.push(resource.kind()? * resource.quantity_scalar());
        }
        let mut created_quantities_bindings = Vec::with_capacity(created_resources.len());
        for resource in created_resources.iter() {
            // Save EC point negation constraints by substracting the scalar instead.
            created_quantities_bindings.push(resource.kind()? * (-resource.quantity_scalar()));
        }
        // Pedersen commit to all quantities
        let delta = consumed_quantities_bindings
            .into_iter()
            .chain(created_quantities_bindings.into_iter())
            .reduce(|acc, quantity_binding| acc + quantity_binding)
            .ok_or(ArmError::InvalidDelta)?
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

    fn hash_consumed_nullifiers(nullifiers: &[Digest]) -> Digest {
        let mut bytes = Vec::new();
        for nf in nullifiers.iter() {
            bytes.append(&mut nf.as_bytes().to_vec().clone());
        }

        Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap()
    }
}
