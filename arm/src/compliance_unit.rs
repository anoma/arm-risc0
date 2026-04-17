//! Compliance unit module containing compliance verification helpers.

pub use arm_core::compliance_unit::ComplianceUnit;

use k256::ProjectivePoint;
use risc0_zkvm::InnerReceipt;

use crate::{
    compliance::{ComplianceInstanceExt, ComplianceWitness},
    constants::COMPLIANCE_VK,
    error::ArmError,
};

#[cfg(feature = "prove")]
use crate::{
    constants::COMPLIANCE_PK,
    proving_system::{prove, ProofType},
};

/// Extension methods for compliance units that require zkvm/k256 functionality.
pub trait ComplianceUnitExt {
    /// Verifies the compliance proof against the instance using the constant verifying key.
    fn verify(&self) -> Result<(), ArmError>;

    /// Obtains the delta from the compliance instance.
    fn delta(&self) -> Result<ProjectivePoint, ArmError>;

    /// Retrieves the inner receipt from the compliance proof.
    fn get_inner_receipt(&self) -> Result<InnerReceipt, ArmError>;
}

impl ComplianceUnitExt for ComplianceUnit {
    fn verify(&self) -> Result<(), ArmError> {
        if let Some(proof) = &self.proof {
            let instance_bytes = self.instance.to_journal()?;
            crate::proving_system::verify(&COMPLIANCE_VK, &instance_bytes, proof)
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing compliance proof".into(),
            ))
        }
    }

    fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.instance.delta_projective()
    }

    fn get_inner_receipt(&self) -> Result<InnerReceipt, ArmError> {
        let inner: InnerReceipt = bincode::deserialize(
            self.proof
                .as_ref()
                .ok_or(ArmError::MissingField("Missing compliance proof"))?,
        )
        .map_err(|_| ArmError::InnerReceiptDeserializationError)?;
        Ok(inner)
    }
}

/// Creates a new compliance unit by proving the given witness.
#[cfg(feature = "prove")]
pub fn create_compliance_unit(
    witness: &ComplianceWitness,
    proof_type: ProofType,
) -> Result<ComplianceUnit, ArmError> {
    let instance = witness.constrain()?;
    let (proof, _instance_bytes) = prove(COMPLIANCE_PK, witness, proof_type)?;
    Ok(ComplianceUnit {
        proof: Some(proof),
        instance,
    })
}
