use crate::{
    constants::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID},
    utils::{groth16_prove, verify as verify_proof},
};
use arm_core::{
    compliance::{ComplianceInstance, ComplianceWitness},
    constants::COMMITMENT_TREE_DEPTH,
};
use risc0_zkvm::{InnerReceipt, Journal, Receipt};
#[cfg(feature = "nif")]
use rustler::NifStruct;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.ComplianceUnit")]
pub struct ComplianceUnit {
    pub proof: Vec<u8>,
    pub instance: Vec<u8>,
}

impl ComplianceUnit {
    pub fn prove(witness: &ComplianceWitness<COMMITMENT_TREE_DEPTH>) -> Self {
        let receipt = groth16_prove(witness, COMPLIANCE_GUEST_ELF);
        ComplianceUnit {
            proof: bincode::serialize(&receipt.inner).unwrap(),
            instance: receipt.journal.bytes,
        }
    }

    pub fn verify(&self) -> bool {
        let inner: InnerReceipt = bincode::deserialize(&self.proof).unwrap();
        let receipt = Receipt::new(inner, self.instance.clone());
        verify_proof(&receipt, COMPLIANCE_GUEST_ID)
    }

    pub fn get_instance(&self) -> ComplianceInstance {
        let journal = Journal {
            bytes: self.instance.clone(),
        };
        // TODO: handle the unwrap properly
        journal.decode().unwrap()
    }
}
