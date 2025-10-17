use crate::{
    compliance::{
        ComplianceInstance, ComplianceSigmabusWitness, ComplianceVarInstance, ComplianceVarWitness,
        ComplianceWitness, SigmaBusCircuitInstance, SigmabusCircuitWitness,
    },
    constants::{
        COMPLIANCE_PK, COMPLIANCE_SIGMABUS_PK, COMPLIANCE_SIGMABUS_VK, COMPLIANCE_VAR_PK,
        COMPLIANCE_VAR_VK, COMPLIANCE_VK,
    },
    error::ArmError,
    proving_system::{journal_to_instance, prove, verify as verify_proof},
    sigma::SigmaProtocol,
};
use k256::ProjectivePoint;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// Compliance Unit Interface.
// It is aligned with the specs. It further exposes convenient functionality.
pub trait CUI {
    type Witness: Serialize;
    type Instance: for<'de> Deserialize<'de>;
    type Delta; // TODO: Can specialize it to a single EC point after adjusting the sigmabus CU.

    /// Computes the compliance proof and populates the compliance unit.
    fn create(witness: &Self::Witness) -> Result<Self, ArmError>
    where
        Self: Sized,
    {
        let (proof_bytes, instance_bytes) = prove(Self::proving_key(), witness)?;
        Self::new(instance_bytes, proof_bytes, None)
    }

    /// Verifies the compliance proof.
    fn verify(&self) -> Result<(), ArmError> {
        if let Some(proof) = &self.proof_bytes() {
            verify_proof(&Self::verifying_key(), &self.instance_bytes(), proof)
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing compliance proof".into(),
            ))
        }
    }

    /// Returns the commitments of the created resources checked in the unit.
    fn created(&self) -> Result<Vec<Digest>, ArmError>;

    /// Returns the nullifiers of the consumed resources checked in the unit.
    fn consumed(&self) -> Result<Vec<Digest>, ArmError>;

    /// Returns the compliance unit's delta.
    fn delta(&self) -> Result<Self::Delta, ArmError>;

    /// Returns the compliance circuit proving key.
    fn proving_key() -> &'static [u8];

    /// Returns the compliance circuit verifying key.
    fn verifying_key() -> Digest;

    /// Returns the instance (public output) of the compliance circuit.
    fn instance(&self) -> Result<Self::Instance, ArmError> {
        journal_to_instance(&self.instance_bytes())
    }

    /// Returns the bytes of the compliance instance.
    fn instance_bytes(&self) -> Vec<u8>;

    /// Returns the bytes of the compliance proof.
    fn proof_bytes(&self) -> Option<Vec<u8>>;

    /// Raw constructor. CUs must at least be aware of the instance and compliance proof.
    /// The delta can be either stored or infered.
    fn new(
        instance_bytes: Vec<u8>,
        proof_bytes: Vec<u8>,
        delta: Option<Self::Delta>,
    ) -> Result<Self, ArmError>
    where
        Self: Sized;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceUnit {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
}

impl CUI for ComplianceUnit {
    type Witness = ComplianceWitness;
    type Instance = ComplianceInstance;
    type Delta = ProjectivePoint;

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VK
    }

    fn created(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(vec![self.instance()?.consumed_nullifier])
    }

    fn consumed(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(vec![self.instance()?.created_commitment])
    }

    fn delta(&self) -> Result<Self::Delta, ArmError> {
        self.instance()?.delta_projective()
    }

    fn instance_bytes(&self) -> Vec<u8> {
        self.instance.clone()
    }

    fn proof_bytes(&self) -> Option<Vec<u8>> {
        self.proof.clone()
    }

    fn new(
        instance_bytes: Vec<u8>,
        proof_bytes: Vec<u8>,
        _: Option<Self::Delta>,
    ) -> Result<Self, ArmError> {
        Ok(ComplianceUnit {
            proof: Some(proof_bytes),
            instance: instance_bytes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceVarUnit {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
}

impl CUI for ComplianceVarUnit {
    type Witness = ComplianceVarWitness;
    type Instance = ComplianceVarInstance;
    type Delta = ProjectivePoint;

    fn created(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(self
            .instance()?
            .created_memorandums
            .iter()
            .map(|memo| memo.resource_commitment)
            .collect())
    }

    fn consumed(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(self
            .instance()?
            .consumed_memorandums
            .iter()
            .map(|memo| memo.resource_nullifier)
            .collect())
    }

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_VAR_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_VAR_VK
    }

    fn delta(&self) -> Result<Self::Delta, ArmError> {
        self.instance()?.delta_projective()
    }

    fn instance_bytes(&self) -> Vec<u8> {
        self.instance.clone()
    }

    fn proof_bytes(&self) -> Option<Vec<u8>> {
        self.proof.clone()
    }

    fn new(
        instance_bytes: Vec<u8>,
        proof_bytes: Vec<u8>,
        _: Option<Self::Delta>,
    ) -> Result<Self, ArmError> {
        Ok(ComplianceVarUnit {
            proof: Some(proof_bytes),
            instance: instance_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ComplianceSigmabusUnit {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
    pub delta: Vec<ProjectivePoint>,
}

impl CUI for ComplianceSigmabusUnit {
    type Witness = ComplianceSigmabusWitness;
    type Instance = SigmaBusCircuitInstance;
    type Delta = Vec<ProjectivePoint>;

    fn create(witness: &ComplianceSigmabusWitness) -> Result<Self, ArmError> {
        // Prove off the zkVM
        let sigma_instance = witness.compute_deltas();
        let sigma_proof = SigmaProtocol::prove(&sigma_instance, &witness.sigma_witness)?;
        // Prove on the zkVM
        let circuit_input =
            SigmabusCircuitWitness::from_sigmabus_witness_proof(witness, &sigma_proof);
        let (circuit_proof, circuit_instance) = prove(COMPLIANCE_SIGMABUS_PK, &circuit_input)?;

        Ok(ComplianceSigmabusUnit {
            proof: Some(circuit_proof),
            instance: circuit_instance,
            delta: sigma_instance,
        })
    }

    fn verify(&self) -> Result<(), ArmError> {
        let circuit_instance = self.instance()?;
        let sigma_proof = circuit_instance.sigma_proof;

        if SigmaProtocol::verify(&self.delta, &sigma_proof).is_err() {
            return Err(ArmError::ProofVerificationFailed(
                "Invalid sigma proof".into(),
            ));
        }
        if let Some(proof) = &self.proof {
            if verify_proof(&COMPLIANCE_SIGMABUS_VK, &self.instance, proof).is_err() {
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

    fn created(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(self
            .instance()?
            .created_memorandums
            .iter()
            .map(|memo| memo.resource_commitment)
            .collect())
    }

    fn consumed(&self) -> Result<Vec<Digest>, ArmError> {
        Ok(self
            .instance()?
            .consumed_memorandums
            .iter()
            .map(|memo| memo.resource_nullifier)
            .collect())
    }

    fn proving_key() -> &'static [u8] {
        COMPLIANCE_SIGMABUS_PK
    }

    fn verifying_key() -> Digest {
        *COMPLIANCE_SIGMABUS_VK
    }

    fn delta(&self) -> Result<Self::Delta, ArmError> {
        Ok(self.delta.clone())
    }

    fn instance_bytes(&self) -> Vec<u8> {
        self.instance.clone()
    }

    fn proof_bytes(&self) -> Option<Vec<u8>> {
        self.proof.clone()
    }

    fn new(
        instance_bytes: Vec<u8>,
        proof_bytes: Vec<u8>,
        delta: Option<Self::Delta>,
    ) -> Result<Self, ArmError> {
        if let Some(delta) = delta {
            Ok(ComplianceSigmabusUnit {
                proof: Some(proof_bytes),
                instance: instance_bytes,
                delta,
            })
        } else {
            Err(ArmError::InvalidDelta)
        }
    }
}
