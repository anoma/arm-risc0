use compliance_circuit::COMPLIANCE_GUEST_ID;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Action {
    pub compliance_units: Vec<Receipt>,
    pub logic_proofs: Vec<Receipt>,
}

impl Action {
    pub fn new(compliance_units: Vec<Receipt>, logic_proofs: Vec<Receipt>) -> Self {
        Action {
            compliance_units,
            logic_proofs,
        }
    }

    pub fn get_compliance_units(&self) -> &Vec<Receipt> {
        &self.compliance_units
    }

    pub fn get_logic_proofs(&self) -> &Vec<Receipt> {
        &self.logic_proofs
    }

    pub fn verify(&self) -> bool {
        for receipt in &self.compliance_units {
            if receipt.verify(COMPLIANCE_GUEST_ID).is_err() {
                return false;
            }
        }

        // TODO: Verify real logic proofs
        for receipt in &self.logic_proofs {
            if receipt.verify(COMPLIANCE_GUEST_ID).is_err() {
                return false;
            }
        }

        // TODO: Verify other checks
        // Actually, the verification should occur on validators/EVM adapter.

        true
    }
}

#[test]
fn test_action() {
    use aarm_core::{compliance::ComplianceWitness, constants::TREE_DEPTH, utils::GenericEnv};
    use bincode;
    use compliance_circuit::COMPLIANCE_GUEST_ELF;
    use risc0_zkvm::{default_prover, ExecutorEnv};
    use serde_bytes::ByteBuf;

    let compliance_witness: ComplianceWitness<TREE_DEPTH> =
        ComplianceWitness::<TREE_DEPTH>::default();
    let generic_env = GenericEnv {
        data: ByteBuf::from(bincode::serialize(&compliance_witness).unwrap()),
    };

    let env = ExecutorEnv::builder()
        .write(&generic_env)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove(env, COMPLIANCE_GUEST_ELF).unwrap().receipt;

    let compliance_units = vec![receipt.clone()];
    let logic_proofs = vec![receipt];

    let action = Action::new(compliance_units, logic_proofs);

    assert!(action.verify());
}
