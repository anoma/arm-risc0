// Maximum number of resources allowed in transactions using the sigmabus compliance circuit.
pub const TX_MAX_RESOURCES: usize = 128;

use crate::{
    compliance::{ComplianceConstraint, INITIAL_ROOT},
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    sigma::{SigmaProof, SigmaWitness},
};
use k256::{elliptic_curve::Field, ProjectivePoint, Scalar};
use risc0_zkvm::Digest;

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
        if consumed_resources.len() + created_resources.len() > TX_MAX_RESOURCES {
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

impl ComplianceConstraint for SigmabusCircuitWitness {
    type Instance = SigmabusCircuitInstance;

    fn constrain(&self) -> Result<Self::Instance, ArmError> {
        // Enforce inner product constraints
        Self::inner_product_constraints(
            &self.consumed_resources,
            &self.created_resources,
            &self.sigma_witness.mcv,
        )?;

        // Enforce constraints related to sigmabus
        Self::sigmabus_constraints(&self.sigma_witness, &self.sigma_proof)?;

        // Enforce all other constraints over resources
        let instance_var = super::var::ComplianceVarWitness {
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
