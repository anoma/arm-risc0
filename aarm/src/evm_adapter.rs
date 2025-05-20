use aarm_core::{compliance::ComplianceInstance, logic_instance::LogicInstance};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterTransaction {
    pub action: Vec<AdapterAction>,
    pub delta_proof: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterAction {
    pub compliance_units: Vec<AdapterComplianceUnit>,
    pub logic_proofs: Vec<AdapterLogicProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterComplianceUnit {
    // The proof corresponds to the seal in risc0
    pub proof: Vec<u8>,
    // The instance corresponds to the journal in risc0
    pub instance: ComplianceInstance,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterLogicProof {
    // The verifying key corresponds to the imageID in risc0
    pub verifying_key: Digest,
    // The proof corresponds to the seal in risc0
    pub proof: Vec<u8>,
    // The instance corresponds to the journal in risc0
    pub instance: LogicInstance,
}

// AdapterDelta is a signature struct corresponding to a tuple of (r,s,v) in EVM
// adapter where r(32 bytes) and s(bytes) are the signature values and v(1 byte)
// is the recovery id.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdapterDelta(Vec<u8>);

impl AdapterDelta {
    pub fn new(bytes: [u8; 65]) -> Self {
        Self(bytes.to_vec())
    }
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }
}
