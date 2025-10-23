use crate::{
    compliance::{
        sigmabus::ComplianceSigmabusInstance, ComplianceInstance, ComplianceSigmabusWitness,
        ComplianceVarInstance, ComplianceVarWitness, ComplianceWitness, ConsumedMemorandum,
        CreatedMemorandum, SigmaBusCircuitInstance, SigmabusCircuitWitness, CI,
    },
    constants::{
        COMPLIANCE_PK, COMPLIANCE_SIGMABUS_PK, COMPLIANCE_SIGMABUS_VK, COMPLIANCE_VAR_PK,
        COMPLIANCE_VAR_VK, COMPLIANCE_VK,
    },
    error::ArmError,
    proving_system::{journal_to_instance, prove, verify as verify_proof},
    sigma::SigmaProtocol,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, EncodedPoint, ProjectivePoint};
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
    pub trait CUInner {
        type Witness: Serialize;
        type Instance: CI + for<'de> Deserialize<'de>;
        const BOUNDED_RESOURCES: bool;

        fn create_inner(witness: &Self::Witness) -> Result<Self, ArmError>
        where
            Self: Sized,
        {
            let (proof_bytes, circuit_instance_bytes) = prove(Self::proving_key(), witness)?;
            Self::new(circuit_instance_bytes, proof_bytes, None)
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

        /// Returns the bytes of the part of the compliance proof generated in RISC0.
        fn circuit_proof_bytes(&self) -> Option<&[u8]>;

        /// Raw constructor. CUs must at least be aware of the instance and compliance proof.
        /// The delta can be either stored or infered.
        fn new(
            circuit_instance_bytes: Vec<u8>,
            circuit_proof_bytes: Vec<u8>,
            delta: Option<EncodedPoint>,
        ) -> Result<Self, ArmError>
        where
            Self: Sized;
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
    const BOUNDED_RESOURCES: bool = false;

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VK
    }

    fn circuit_instance_bytes(&self) -> &[u8] {
        self.instance.as_slice()
    }

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.proof.as_ref().map(Vec::as_ref)
    }

    fn new(
        circuit_instance_bytes: Vec<u8>,
        circuit_proof_bytes: Vec<u8>,
        _: Option<EncodedPoint>,
    ) -> Result<Self, ArmError> {
        Ok(ComplianceUnit {
            proof: Some(circuit_proof_bytes),
            instance: circuit_instance_bytes,
        })
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
    const BOUNDED_RESOURCES: bool = false;

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_VAR_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VAR_VK
    }

    fn circuit_instance_bytes(&self) -> &[u8] {
        self.instance.as_slice()
    }

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.proof.as_ref().map(Vec::as_ref)
    }

    fn new(
        circuit_instance_bytes: Vec<u8>,
        circuit_proof_bytes: Vec<u8>,
        _: Option<EncodedPoint>,
    ) -> Result<Self, ArmError> {
        Ok(ComplianceVarUnit {
            proof: Some(circuit_proof_bytes),
            instance: circuit_instance_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ComplianceSigmabusUnit {
    pub circuit_proof: Option<Vec<u8>>,
    pub circuit_instance: Vec<u8>,
    pub delta: EncodedPoint,
}

impl CUInner for ComplianceSigmabusUnit {
    type Witness = ComplianceSigmabusWitness;
    type Instance = ComplianceSigmabusInstance;
    const BOUNDED_RESOURCES: bool = true;

    fn create_inner(witness: &ComplianceSigmabusWitness) -> Result<Self, ArmError> {
        // Prove off the zkVM
        let sp = SigmaProtocol::new(witness.sigma_witness.mcv.len());
        let sigma_instance = witness.compute_delta();
        let sigma_proof = sp.prove(&sigma_instance, &witness.sigma_witness)?;
        // Prove on the zkVM
        let circuit_input =
            SigmabusCircuitWitness::from_sigmabus_witness_proof(witness, &sigma_proof);
        let (circuit_proof, circuit_instance) = prove(COMPLIANCE_SIGMABUS_PK, &circuit_input)?;

        ComplianceSigmabusUnit::new(
            circuit_instance,
            circuit_proof,
            Some(sigma_instance.to_encoded_point(true)),
        )
    }

    fn verify_inner(&self) -> Result<(), ArmError> {
        let sigmabus_instance = self.instance()?;
        let circuit_instance = sigmabus_instance.circuit_instance;
        let sigma_proof = circuit_instance.sigma_proof;

        let sp = SigmaProtocol::new(sigma_proof.response1.len());

        if sp.verify(&self.delta()?, &sigma_proof).is_err() {
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

    fn circuit_proof_bytes(&self) -> Option<&[u8]> {
        self.circuit_proof.as_ref().map(Vec::as_ref)
    }

    fn new(
        circuit_instance_bytes: Vec<u8>,
        circuit_proof_bytes: Vec<u8>,
        delta: Option<EncodedPoint>,
    ) -> Result<Self, ArmError> {
        if let Some(delta) = delta {
            Ok(ComplianceSigmabusUnit {
                circuit_proof: Some(circuit_proof_bytes),
                circuit_instance: circuit_instance_bytes,
                delta,
            })
        } else {
            Err(ArmError::InvalidDelta)
        }
    }
}
