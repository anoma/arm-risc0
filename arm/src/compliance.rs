// Size hard-coded to two resources per unit
const COMPLIANCE_INSTANCE_SIZE: usize = 56;
// Maximum number of resources allowed in transactions using the sigmabus compliance circuit.
pub const TX_MAX_RESOURCES: usize = 128;

use crate::{
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    sigma::{SigmaProof, SigmaWitness},
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
use serde_with::serde_as;
lazy_static! {
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

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

    pub fn consumed_resource_logic(&self) -> Digest {
        self.consumed_resource.logic_ref
    }

    pub fn created_resource_logic(&self) -> Digest {
        self.created_resource.logic_ref
    }

    pub fn consumed_commitment(&self) -> Digest {
        self.consumed_resource.commitment()
    }

    pub fn created_commitment(&self) -> Digest {
        self.created_resource.commitment()
    }

    pub fn consumed_nullifier(&self, cm: &Digest) -> Result<Digest, ArmError> {
        self.consumed_resource
            .nullifier_from_commitment(&self.nf_key, cm)
    }

    pub fn consumed_commitment_tree_root(&self, cm: &Digest) -> Digest {
        if self.consumed_resource.is_ephemeral {
            self.ephemeral_root
        } else {
            self.merkle_path.root(cm)
        }
    }

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
        let delta = consumed_kind * self.consumed_resource.quantity_scalar()
            - created_kind * self.created_resource.quantity_scalar()
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

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.consumed_nullifier.as_bytes());
        msg.extend_from_slice(self.created_commitment.as_bytes());
        msg
    }
}

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
    pub fn constrain(&self) -> Result<ComplianceVarInstance, ArmError> {
        let mut compliance_instance = self.constrain_resources()?;

        // Generate the delta commitment of the compliance unit.
        let (delta_x, delta_y) = self.delta()?;

        compliance_instance.delta_x = delta_x;
        compliance_instance.delta_y = delta_y;

        Ok(compliance_instance)
    }

    // It does not enforce Delta constraints
    fn constrain_resources(&self) -> Result<ComplianceVarInstance, ArmError> {
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
        for (index, resource) in self.created_resources.iter().enumerate() {
            // Generate the commitment
            let cm = resource.commitment();
            created_commitments.push(cm);

            // Re-derive the nonce and enforce equality.
            let correct_nonce = Resource::derive_nonce(index, &consumed_nullifiers)?;
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

pub struct ComplianceSigmabusWitness {
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
    /// The witness of the sigma protocol
    pub sigma_witness: SigmaWitness,
}

impl ComplianceSigmabusWitness {
    /// Useful for tests.
    pub fn from_resources_with_fixed_path(
        consumed_resources: &[Resource],
        nf_keys: &[NullifierKey],
        created_resources: &[Resource],
    ) -> Result<ComplianceSigmabusWitness, ArmError> {
        if consumed_resources.len()+created_resources.len() > TX_MAX_RESOURCES {
            return Err(ArmError::InvalidMcv);
        }
        let mut rng = rand::thread_rng();

        let (kinds, signed_quantities) = ComplianceSigmabusWitness::compute_kinds_quantites(
            consumed_resources,
            created_resources,
        );

        let mcv = ComplianceSigmabusWitness::compute_inner_products(&kinds, &signed_quantities)?;

        let rcv: Vec<Scalar> = (0..TX_MAX_RESOURCES)
            .map(|_| Scalar::random(&mut rng))
            .collect();

        let sigma_witness = SigmaWitness::new(&mcv, &rcv)?;

        Ok(ComplianceSigmabusWitness {
            consumed_resources: consumed_resources.to_vec(),
            created_resources: created_resources.to_vec(),
            merkle_paths: vec![MerklePath::empty(); consumed_resources.len()],
            ephemeral_root: *INITIAL_ROOT,
            nf_keys: nf_keys.to_vec(),
            sigma_witness,
        })
    }

    /// Pedersen commit seperately to the components of the message vector `mcv`.
    /// Uses `rcv` as the commitment randomness.
    pub fn compute_deltas(&self) -> Vec<ProjectivePoint> {
        SigmaWitness::pedersen_commit_batch(&self.sigma_witness.mcv, &self.sigma_witness.rcv)
    }

    /// Compute the kinds and signed quantities as scalars. It is guaranteed
    /// the output vectors have the same length, and that the i-th kind and
    /// i-th quantity come from the same resource.
    pub fn compute_kinds_quantites(
        consumed_resources: &[Resource],
        created_resources: &[Resource],
    ) -> (Vec<Scalar>, Vec<Scalar>) {
        let kinds: Vec<Scalar> = consumed_resources
            .iter()
            .chain(created_resources.iter())
            .map(|res| res.kind_scalar())
            .collect();
        let mut signed_quantities: Vec<Scalar> = consumed_resources
            .iter()
            .map(|res| res.quantity_scalar()) // the quantity
            .collect();
        signed_quantities.append(
            &mut created_resources
                .iter()
                .map(|res| -res.quantity_scalar()) // the negated quantity
                .collect(),
        );

        (kinds, signed_quantities)
    }

    /// Succesively compute kinds powers and their inner products with the quantities.
    /// Errors if input vectors have distinct length.
    /// The output vector has length [TX_MAX_RESOURCES].
    pub fn compute_inner_products(
        kinds: &[Scalar],
        signed_quantities: &[Scalar],
    ) -> Result<Vec<Scalar>, ArmError> {
        if kinds.len() != signed_quantities.len() {
            return Err(ArmError::InvalidMcv);
        }
        let mut kinds_j_pow = Vec::with_capacity(kinds.len());
        let mut mcv = Vec::with_capacity(TX_MAX_RESOURCES);
        for j in 0..TX_MAX_RESOURCES {
            // next power
            kinds_j_pow = match j {
                0 => vec![Scalar::ONE; kinds.len()],
                1 => kinds.to_vec(),
                _ => kinds_j_pow.iter().map(|s| s * s).collect(),
            };
            let inner_product_j = kinds_j_pow
                .iter()
                .zip(signed_quantities.iter())
                .fold(Scalar::ZERO, |inner_product, (l, r)| inner_product + l * r);

            mcv.push(inner_product_j);
        }
        Ok(mcv)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmabusCircuitWitness {
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
    /// The witness of the sigma protocol
    pub sigma_witness: SigmaWitness,
    /// The proof of the sigma protocol
    pub sigma_proof: SigmaProof,
}

impl SigmabusCircuitWitness {
    pub fn from_sigmabus_witness_proof(
        witness: &ComplianceSigmabusWitness,
        sigma_proof: &SigmaProof,
    ) -> Self {
        SigmabusCircuitWitness {
            consumed_resources: witness.consumed_resources.clone(),
            created_resources: witness.created_resources.clone(),
            merkle_paths: witness.merkle_paths.clone(),
            ephemeral_root: witness.ephemeral_root,
            nf_keys: witness.nf_keys.clone(),
            sigma_witness: witness.sigma_witness.clone(),
            sigma_proof: sigma_proof.clone(),
        }
    }

    pub fn constrain(&self) -> Result<SigmabusCircuitInstance, ArmError> {
        // Enforce inner product constraints
        Self::inner_product_constraints(
            &self.consumed_resources,
            &self.created_resources,
            &self.sigma_witness.mcv,
        )?;

        // Enforce constraints related to sigmabus
        Self::sigmabus_constraints(&self.sigma_witness, &self.sigma_proof)?;

        // Enforce all other constraints over resources
        let instance_var = ComplianceVarWitness {
            consumed_resources: self.consumed_resources.clone(),
            created_resources: self.created_resources.clone(),
            merkle_paths: self.merkle_paths.clone(),
            ephemeral_root: self.ephemeral_root,
            nf_keys: self.nf_keys.clone(),
            rcv: Vec::new(), // Dummy
        }
        .constrain_resources()?;

        Ok(SigmabusCircuitInstance {
            consumed_nullifiers: instance_var.consumed_nullifiers,
            created_commitments: instance_var.created_commitments,
            consumed_logic_refs: instance_var.consumed_logic_refs,
            consumed_commitments_tree_roots: instance_var.consumed_commitments_tree_roots,
            created_logic_refs: instance_var.created_logic_refs,
            sigma_proof: self.sigma_proof.clone(),
        })
    }

    fn inner_product_constraints(
        consumed_resources: &[Resource],
        created_resources: &[Resource],
        mcv: &[Scalar],
    ) -> Result<(), ArmError> {
        let (kinds, signed_quantities) = ComplianceSigmabusWitness::compute_kinds_quantites(
            consumed_resources,
            created_resources,
        );
        //Enforce mcv are the correct inner products.
        let correct_mcv =
            ComplianceSigmabusWitness::compute_inner_products(&kinds, &signed_quantities)?;
        if mcv != correct_mcv {
            Err(ArmError::InvalidMcv)
        } else {
            Ok(())
        }
    }

    fn sigmabus_constraints(
        sigma_witness: &SigmaWitness,
        sigma_proof: &SigmaProof,
    ) -> Result<(), ArmError> {
        // Enforce correct commitment
        let correct_commitment = sigma_witness.commit();
        if sigma_proof.commitment_to_witness != correct_commitment {
            return Err(ArmError::InvalidMcv);
        }

        // Enforce consistent sigma responses
        let correct_response1 = SigmaWitness::response(
            &sigma_witness.mcv,
            &sigma_witness.blinding_mcv,
            &sigma_proof.challenge,
        )?;
        let correct_response2 = SigmaWitness::response(
            &sigma_witness.rcv,
            &sigma_witness.blinding_rcv,
            &sigma_proof.challenge,
        )?;
        if sigma_proof.response1 != correct_response1 || sigma_proof.response2 != correct_response2
        {
            return Err(ArmError::InvalidMcv);
        }

        //All good
        Ok(())
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

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SigmabusCircuitInstance {
    pub consumed_nullifiers: Vec<Digest>,
    pub created_commitments: Vec<Digest>,
    pub consumed_logic_refs: Vec<Digest>,
    pub consumed_commitments_tree_roots: Vec<Digest>,
    pub created_logic_refs: Vec<Digest>,
    pub sigma_proof: SigmaProof,
}
