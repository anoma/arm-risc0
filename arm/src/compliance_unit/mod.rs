pub(crate) mod sigma;

use crate::{
    compliance::{
        minimal::ComplianceInstanceWords, sigmabus::ComplianceSigmabusInstance, CIWords,
        ComplianceInstance, ComplianceSigmabusWitness, ComplianceVarInstance, ComplianceVarWitness,
        ComplianceWitness, ConsumedMemorandum, CreatedMemorandum, SigmaBusCircuitInstance,
        SigmabusCircuitWitness, CI,
    },
    compliance_unit::sigma::{SigmaProof, SigmaProofShort, SigmaProtocol},
    constants::{
        COMPLIANCE_PK, COMPLIANCE_SIGMABUS_PK, COMPLIANCE_SIGMABUS_VK, COMPLIANCE_VAR_PK,
        COMPLIANCE_VAR_VK, COMPLIANCE_VK,
    },
    error::ArmError,
    proving_system::{journal_to_instance, prove, verify as verify_proof},
    utils::bytes_to_words,
};
use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// Compliance Unit Interface.
pub trait CUI {
    type Witness;
    type Instance;

    /// Computes the compliance proof and populates the compliance unit.
    fn create(witness: &Self::Witness) -> Result<Self, ArmError>
    where
        Self: Sized;

    /// Verifies the compliance proof.
    fn verify(&self) -> Result<(), ArmError>;

    /// Returns the public information of the created resources checked in this unit.
    /// (Includes the commitments.)
    fn created(&self) -> Result<Vec<CreatedMemorandum>, ArmError>;

    /// Returns the public information of the consumed resources checked in this unit.
    /// (Includes the nullifiers.)
    fn consumed(&self) -> Result<Vec<ConsumedMemorandum>, ArmError>;

    /// Returns the compliance unit's delta.
    fn delta(&self) -> Result<ProjectivePoint, ArmError>;
}

pub(crate) mod inner_cui {
    use super::*;
    /// CUs should implement this trait instead of implementing directly the high-level [CUI].
    // The default implementations of this inner trait are only for CUs fully constrained in RISC0.
    pub trait CUInner: Clone {
        type Witness: Serialize;
        type Instance: CI + for<'de> Deserialize<'de>;

        fn create_inner(witness: &Self::Witness) -> Result<Self, ArmError>
        where
            Self: Sized,
        {
            let (proof_bytes, circuit_instance_bytes) = prove(Self::proving_key(), witness)?;
            Ok(Self::new(circuit_instance_bytes, proof_bytes))
        }

        fn verify_inner(&self) -> Result<(), ArmError> {
            if let Some(proof) = &self.circuit_proof_bytes() {
                verify_proof(&Self::verifying_key(), self.circuit_instance_bytes(), proof)
            } else {
                Err(ArmError::ProofVerificationFailed(
                    "Missing compliance proof".into(),
                ))
            }
        }

        /// Returns the proving key of the compliance program enforced in RISC0.
        fn proving_key() -> &'static [u8];

        /// Returns the verifying key of the compliance program enforced in RISC0.
        fn verifying_key() -> Digest;

        /// Returns the instance (public output) checked in this unit.
        fn instance(&self) -> Result<Self::Instance, ArmError> {
            journal_to_instance(self.circuit_instance_bytes())
        }

        /// Returns the bytes of the part of the instance checked in RISC0.
        fn circuit_instance_bytes(&self) -> &[u8];

        /// Returns the u32 words of the part of the instance checked in RISC0.
        /// This is useful for aggregation, where the instance is passed as input
        /// to the aggregation circuit.
        fn circuit_instance_words(&self) -> Result<CIWords, ArmError>;

        /// Returns the bytes of the part of the compliance proof generated in RISC0.
        fn circuit_proof_bytes(&self) -> Option<&[u8]>;

        /// Sets the circuit proof to `None`.  
        fn unset_circuit_proof(&mut self);

        /// Returns the instance/proof of the sigma protocol. Used only in [ComplianceSigmabusUnit]
        fn get_sigma_verifier_inputs(&self) -> Result<(ProjectivePoint, SigmaProof), ArmError> {
            Err(ArmError::MissingField(
                "the unit does not use a sigma protocol",
            ))
        }

        /// Raw constructor. CUs must at least be aware of the instance and compliance proof.
        fn new(circuit_instance_bytes: Vec<u8>, circuit_proof_bytes: Vec<u8>) -> Self;
    }
}

pub(crate) use inner_cui::CUInner;

impl<CU: CUInner> CUI for CU {
    type Witness = <CU as CUInner>::Witness;

    type Instance = <CU as CUInner>::Instance;

    fn create(witness: &Self::Witness) -> Result<Self, ArmError>
    where
        Self: Sized,
    {
        Self::create_inner(witness)
    }

    fn verify(&self) -> Result<(), ArmError> {
        self.verify_inner()
    }

    fn created(&self) -> Result<Vec<CreatedMemorandum>, ArmError> {
        Ok(self.instance()?.created_info())
    }

    fn consumed(&self) -> Result<Vec<ConsumedMemorandum>, ArmError> {
        Ok(self.instance()?.consumed_info())
    }

    fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.instance()?.delta()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceUnit {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
}

impl CUInner for ComplianceUnit {
    type Witness = ComplianceWitness;
    type Instance = ComplianceInstance;

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VK
    }

    fn circuit_instance_bytes(&self) -> &[u8] {
        self.instance.as_slice()
    }

    fn circuit_instance_words(&self) -> Result<CIWords, ArmError> {
        Ok(CIWords::FixedSize(ComplianceInstanceWords {
            u32_words: bytes_to_words(&self.instance)
                .try_into()
                .map_err(|_| ArmError::InstanceSerializationFailed)?,
        }))
    }

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.proof.as_ref().map(Vec::as_ref)
    }

    fn unset_circuit_proof(&mut self) {
        self.proof = None;
    }

    fn new(circuit_instance_bytes: Vec<u8>, circuit_proof_bytes: Vec<u8>) -> Self {
        ComplianceUnit {
            proof: Some(circuit_proof_bytes),
            instance: circuit_instance_bytes,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceVarUnit {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
}

impl CUInner for ComplianceVarUnit {
    type Witness = ComplianceVarWitness;
    type Instance = ComplianceVarInstance;

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_VAR_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VAR_VK
    }

    fn circuit_instance_bytes(&self) -> &[u8] {
        self.instance.as_slice()
    }

    fn circuit_instance_words(&self) -> Result<CIWords, ArmError> {
        Ok(CIWords::VariableSize(bytes_to_words(&self.instance)))
    }

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.proof.as_ref().map(Vec::as_ref)
    }

    fn unset_circuit_proof(&mut self) {
        self.proof = None;
    }

    fn new(circuit_instance_bytes: Vec<u8>, circuit_proof_bytes: Vec<u8>) -> Self {
        ComplianceVarUnit {
            proof: Some(circuit_proof_bytes),
            instance: circuit_instance_bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ComplianceSigmabusUnit {
    /// The RISC0 proof
    pub circuit_proof: Option<Vec<u8>>,
    /// The RISC0 instance
    pub circuit_instance: Vec<u8>,
    // The first message of the sigma proof.
    pub sp_first_message: EncodedPoint,
    // The delta of the unit.
    pub delta: EncodedPoint,
}

impl CUInner for ComplianceSigmabusUnit {
    type Witness = ComplianceSigmabusWitness;
    type Instance = ComplianceSigmabusInstance;

    fn create_inner(witness: &ComplianceSigmabusWitness) -> Result<Self, ArmError> {
        // Prove off the zkVM
        let sigma_instance = witness.compute_delta();
        let sigma_proof = SigmaProtocol::prove(&sigma_instance, &witness.sigma_witness)?;
        // Prove on the zkVM
        let circuit_input = SigmabusCircuitWitness::from_sigmabus_witness_proof(
            witness,
            &SigmaProofShort::from_sigmaproof(&sigma_proof),
        );
        let (circuit_proof, circuit_instance) = prove(COMPLIANCE_SIGMABUS_PK, &circuit_input)?;

        Ok(ComplianceSigmabusUnit {
            circuit_proof: Some(circuit_proof),
            circuit_instance,
            sp_first_message: sigma_proof.first_message,
            delta: sigma_instance,
        })
    }

    fn verify_inner(&self) -> Result<(), ArmError> {
        let (sigma_instance, sigma_proof) = self.get_sigma_verifier_inputs()?;
        if SigmaProtocol::verify(&sigma_instance, &sigma_proof).is_err() {
            return Err(ArmError::ProofVerificationFailed(
                "Invalid sigma proof".into(),
            ));
        }
        if let Some(circuit_proof) = self.circuit_proof_bytes() {
            if verify_proof(
                &COMPLIANCE_SIGMABUS_VK,
                self.circuit_instance_bytes(),
                circuit_proof,
            )
            .is_err()
            {
                return Err(ArmError::ProofVerificationFailed(
                    "Invalid compliance circuit proof".into(),
                ));
            }
            Ok(())
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing compliance circuit proof".into(),
            ))
        }
    }

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_SIGMABUS_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_SIGMABUS_VK
    }

    fn instance(&self) -> Result<ComplianceSigmabusInstance, ArmError> {
        let circuit_instance: SigmaBusCircuitInstance =
            journal_to_instance(self.circuit_instance_bytes())?;

        Ok(ComplianceSigmabusInstance {
            circuit_instance,
            delta: self.delta,
        })
    }

    fn circuit_instance_bytes(&self) -> &[u8] {
        self.circuit_instance.as_slice()
    }

    fn circuit_instance_words(&self) -> Result<CIWords, ArmError> {
        Ok(CIWords::VariableSize(bytes_to_words(
            &self.circuit_instance,
        )))
    }

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.circuit_proof.as_ref().map(Vec::as_ref)
    }

    fn unset_circuit_proof(&mut self) {
        self.circuit_proof = None;
    }

    fn get_sigma_verifier_inputs(&self) -> Result<(ProjectivePoint, SigmaProof), ArmError> {
        let sigma_proof_short = self.instance()?.circuit_instance.sigma_proof;
        let sigma_proof = SigmaProof::from_first_message_and_sigmaproof_short(
            &self.sp_first_message,
            &sigma_proof_short,
        );
        Ok((
            ProjectivePoint::from_encoded_point(&self.delta)
                .into_option()
                .ok_or(ArmError::ProofVerificationFailed("Bad delta format".into()))?,
            sigma_proof,
        ))
    }

    fn new(_: Vec<u8>, _: Vec<u8>) -> Self {
        unimplemented!()
    }
}
