use crate::{
    compliance::{ComplianceConstraint, INITIAL_ROOT},
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
    /// The consumed resources.
    pub consumed_resources: Vec<Resource>,
    /// The created resources.
    pub created_resources: Vec<Resource>,
    /// The paths from the consumed commitments to the roots in the commitment trees
    pub merkle_paths: Vec<MerklePath>,
    /// The existing root for ephemeral resources
    pub ephemeral_root: Digest,
    /// Nullifier keys of the consumed resources
    pub nf_keys: Vec<NullifierKey>,
    /// Random scalar for delta commitment
    pub rcv: Vec<u8>,
}

impl ComplianceVarWitness {
    /// It does not enforce Delta constraints
    pub(super) fn constrain_resources(&self) -> Result<ComplianceVarInstance, ArmError> {
        let mut consumed_logic_refs = Vec::new();
        let mut consumed_commitments_tree_roots = Vec::new();
        let mut consumed_nullifiers = Vec::new();
        let mut created_commitments = Vec::new();
        let mut created_logic_refs = Vec::new();

        // Constraints for consumed resources.
        for (index, resource) in self.consumed_resources.iter().enumerate() {
            // Re-generate the commitment and the Merkle root.
            let cm = resource.commitment();
            let root = self.consumed_commitment_tree_root(index, &cm)?;
            consumed_commitments_tree_roots.push(root);

            // Generate the nullifier
            let nf = resource.nullifier(
                self.nf_keys
                    .get(index)
                    .ok_or(ArmError::InvalidResourceNonce)?,
            )?;
            consumed_nullifiers.push(nf);

            // Read resource logic vk.
            consumed_logic_refs.push(resource.logic_ref);
        }

        // Constraints for created resources.
        let consumed_nullifiers_digest = Self::hash_consumed_nullifiers(&consumed_nullifiers);
        for (index, resource) in self.created_resources.iter().enumerate() {
            // Generate the commitment
            let cm = resource.commitment();
            created_commitments.push(cm);

            // Re-derive the nonce and enforce equality.
            let correct_nonce = Resource::derive_nonce(index, consumed_nullifiers_digest)?;
            if correct_nonce != resource.nonce {
                return Err(ArmError::InvalidResourceNonce);
            }

            // Read the resource logic vk
            created_logic_refs.push(resource.logic_ref);
        }

        // All good.
        Ok(ComplianceVarInstance {
            consumed_nullifiers,
            created_commitments,
            consumed_logic_refs,
            consumed_commitments_tree_roots,
            created_logic_refs,
            delta_x: [0u32; 8], // Delta constraints not enforced yet.
            delta_y: [0u32; 8],
        })
    }

    // TODO: Handle error.
    pub fn hash_consumed_nullifiers(nullifiers: &[Digest]) -> Digest {
        let mut bytes = Vec::new();
        for nf in nullifiers.iter() {
            bytes.append(&mut nf.as_bytes().to_vec().clone());
        }

        Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap()
    }

    /// Returns the Merkle root for the [MerklePath] at the `index` position
    /// and the passed consumed commitment.
    pub fn consumed_commitment_tree_root(
        &self,
        index: usize,
        cm: &Digest,
    ) -> Result<Digest, ArmError> {
        if self
            .consumed_resources
            .get(index)
            .ok_or(ArmError::MissingField("No resource found at passed index"))?
            .is_ephemeral
        {
            Ok(self.ephemeral_root)
        } else {
            Ok(self
                .merkle_paths
                .get(index)
                .ok_or(ArmError::MissingField(
                    "No merkle path found at passed index",
                ))?
                .root(cm))
        }
    }

    /// Computes the Delta commitment of the (variable) compliance unit.
    pub fn delta(&self) -> Result<([u32; 8], [u32; 8]), ArmError> {
        let rcv_array: [u8; 32] = self
            .rcv
            .as_slice()
            .try_into()
            .map_err(|_| ArmError::InvalidRcv)?;
        let rcv_scalar = Scalar::from_repr(rcv_array.into())
            .into_option()
            .ok_or(ArmError::InvalidRcv)?;

        let mut consumed_quantities_bindings = Vec::new();
        for res in self.consumed_resources.iter() {
            consumed_quantities_bindings.push(res.kind()? * res.quantity_scalar());
        }
        let mut created_quantities_bindings = Vec::new();
        for res in self.consumed_resources.iter() {
            // Save EC point negation constraints by substracting the scalar instead.
            created_quantities_bindings.push(res.kind()? * (-res.quantity_scalar()));
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

    // Only for tests
    pub fn with_fixed_rcv(
        consumed_resources: Vec<Resource>,
        nf_keys: Vec<NullifierKey>,
        created_resources: Vec<Resource>,
    ) -> Self {
        assert_eq!(consumed_resources.len(), nf_keys.len());
        let old_num = consumed_resources.len();
        ComplianceVarWitness {
            consumed_resources,
            created_resources,
            merkle_paths: vec![MerklePath::default(); old_num], // This works for compliance unit tests.
            rcv: Scalar::ONE.to_bytes().to_vec(),
            nf_keys,
            ephemeral_root: *INITIAL_ROOT,
        }
    }
}

impl ComplianceConstraint for ComplianceVarWitness {
    type Instance = ComplianceVarInstance;

    fn constrain(&self) -> Result<Self::Instance, ArmError> {
        let mut compliance_instance = self.constrain_resources()?;

        // Generate the delta commitment of the compliance unit.
        let (delta_x, delta_y) = self.delta()?;

        compliance_instance.delta_x = delta_x;
        compliance_instance.delta_y = delta_y;

        Ok(compliance_instance)
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceVarInstance {
    pub consumed_nullifiers: Vec<Digest>,
    pub created_commitments: Vec<Digest>,
    pub consumed_logic_refs: Vec<Digest>,
    pub consumed_commitments_tree_roots: Vec<Digest>,
    pub created_logic_refs: Vec<Digest>,
    // Use u32 array to avoid padding issues in risc0
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
