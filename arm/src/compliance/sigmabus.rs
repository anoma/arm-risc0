// Maximum number of resources allowed in transactions using the sigmabus compliance circuit.
pub const TX_MAX_RESOURCES: usize = 128;

use crate::{
    compliance::{
        var::var_constraints::constrain_resources, ComplianceCircuit, ComplianceVarWitness,
        ConsumedDatum, ConsumedMemorandum, CreatedMemorandum, CI, INITIAL_ROOT,
    },
    compliance_unit::sigma::{PedersenCommitmentScheme, SigmaProofShort, SigmaWitness},
    error::ArmError,
    resource::Resource,
};
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, ProjectivePoint, Scalar,
};
use risc0_zkvm::Digest;
use serde::Serialize;

#[derive(Serialize)]
pub struct ComplianceSigmabusWitness {
    /// The private information of the CU's resources
    pub var_witness: ComplianceVarWitness,
    /// The witness of the sigma protocol
    pub sigma_witness: SigmaWitness,
}

impl ComplianceSigmabusWitness {
    pub fn from_resources_info(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
    ) -> Result<Self, ArmError> {
        Self::from_resources_info_with_eph_root(consumed_data, created_resources, *INITIAL_ROOT)
    }
    pub fn from_resources_info_with_eph_root(
        consumed_data: &[ConsumedDatum],
        created_resources: &[Resource],
        latest_root: Digest,
    ) -> Result<Self, ArmError> {
        if consumed_data.len() + created_resources.len() > TX_MAX_RESOURCES {
            return Err(ArmError::InvalidComplianceWitness);
        }
        let var_witness = ComplianceVarWitness::from_resources_info_with_eph_root(
            consumed_data,
            created_resources,
            latest_root,
        );

        // Generate the sigma witness.
        let consumed_resources: Vec<Resource> =
            consumed_data.iter().map(|datum| datum.resource).collect();
        let (kinds, signed_quantities) =
            sigmabus_constraints::compute_kinds_quantites(&consumed_resources, created_resources);
        let mcv = sigmabus_constraints::compute_inner_products(&kinds, &signed_quantities)?;

        let sigma_witness = SigmaWitness::new(&mcv, &var_witness.rcv_scalar);

        Ok(ComplianceSigmabusWitness {
            var_witness,
            sigma_witness,
        })
    }

    /// Pedersen commit to the message vector `mcv`.
    /// Uses `rcv` as the commitment randomness.
    pub fn compute_delta(&self) -> EncodedPoint {
        PedersenCommitmentScheme::commit(&self.sigma_witness.mcv, &self.sigma_witness.rcv)
            .to_encoded_point(true)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmabusCircuitWitness {
    /// The CU's resources private information
    pub var_witness: ComplianceVarWitness,
    /// The witness of the sigma protocol
    pub sigma_witness: SigmaWitness,
    /// The proof of the sigma protocol
    pub sigma_proof: SigmaProofShort,
}

impl SigmabusCircuitWitness {
    pub fn from_sigmabus_witness_proof(
        witness: &ComplianceSigmabusWitness,
        sigma_proof: &SigmaProofShort,
    ) -> Self {
        SigmabusCircuitWitness {
            var_witness: witness.var_witness.clone(),
            sigma_witness: witness.sigma_witness.clone(),
            sigma_proof: sigma_proof.clone(),
        }
    }
}

impl ComplianceCircuit for SigmabusCircuitWitness {
    type Instance = SigmaBusCircuitInstance;

    fn constrain(&self) -> Result<Self::Instance, ArmError> {
        let consumed_resources: Vec<Resource> = self
            .var_witness
            .consumed_data
            .iter()
            .map(|datum| datum.resource)
            .collect();
        let (kinds, signed_quantities) = sigmabus_constraints::compute_kinds_quantites(
            &consumed_resources,
            &self.var_witness.created_resources,
        );
        //Enforce mcv are the correct inner products.
        let correct_mcv = sigmabus_constraints::compute_inner_products(&kinds, &signed_quantities)?;
        if self.sigma_witness.mcv != correct_mcv {
            return Err(ArmError::InvalidMcv);
        }

        // Enforce constraints related to the sigmabus trick
        sigmabus_constraints::enforce_correct_sigmabus_commitment(
            &self.sigma_witness,
            &self.sigma_proof,
        )?;
        sigmabus_constraints::enforce_consistent_sigma_responses(
            &self.sigma_witness,
            &self.sigma_proof,
        )?;

        // Enforce all other constraints over resources
        let (consumed_memorandums, created_memorandums) = constrain_resources(
            &self.var_witness.consumed_data,
            &self.var_witness.created_resources,
            self.var_witness.ephemeral_root,
        )?;

        Ok(SigmaBusCircuitInstance {
            consumed_memorandums,
            created_memorandums,
            sigma_proof: self.sigma_proof.clone(),
        })
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SigmaBusCircuitInstance {
    /// Public information of consumed resources
    pub consumed_memorandums: Vec<ConsumedMemorandum>,
    /// Public information of created resources
    pub created_memorandums: Vec<CreatedMemorandum>,
    /// Instead of the Delta commitment.
    pub sigma_proof: SigmaProofShort,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ComplianceSigmabusInstance {
    pub circuit_instance: SigmaBusCircuitInstance,
    pub delta: EncodedPoint,
}

impl CI for ComplianceSigmabusInstance {
    fn consumed_info(&self) -> Vec<ConsumedMemorandum> {
        self.circuit_instance.consumed_memorandums.clone()
    }

    fn created_info(&self) -> Vec<CreatedMemorandum> {
        self.circuit_instance.created_memorandums.clone()
    }

    fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        ProjectivePoint::from_encoded_point(&self.delta)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }
}

/// Constraints specific to sigmabus compliance units.
mod sigmabus_constraints {
    use super::*;

    /// Compute the scalar vectors of kinds and signed quantities. It is guaranteed
    /// the output vectors have the same length, and that the i-th kind and
    /// i-th quantity come from the same resource.
    pub(super) fn compute_kinds_quantites(
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
    pub(super) fn compute_inner_products(
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

    pub(super) fn enforce_correct_sigmabus_commitment(
        sigma_witness: &SigmaWitness,
        sigma_proof: &SigmaProofShort,
    ) -> Result<(), ArmError> {
        let correct_commitment = sigma_witness.commit();
        if sigma_proof.commitment_to_witness != correct_commitment {
            Err(ArmError::InvalidMcv)
        } else {
            Ok(())
        }
    }

    pub(super) fn enforce_consistent_sigma_responses(
        sigma_witness: &SigmaWitness,
        sigma_proof: &SigmaProofShort,
    ) -> Result<(), ArmError> {
        let correct_response1 = SigmaWitness::first_response(
            &sigma_witness.mcv,
            &sigma_witness.blinding_mcv,
            &sigma_proof.challenge,
        )?;
        let correct_response2 = SigmaWitness::second_response(
            &sigma_witness.rcv,
            &sigma_witness.blinding_rcv,
            &sigma_proof.challenge,
        );
        if sigma_proof.response1 != correct_response1 || sigma_proof.response2 != correct_response2
        {
            Err(ArmError::InvalidMcv)
        } else {
            Ok(())
        }
    }
}
