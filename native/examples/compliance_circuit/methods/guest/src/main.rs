use aarm_core::{
    compliance::{ComplianceCircuit, ComplianceInstance, ComplianceWitness},
    constants::TREE_DEPTH,
};
use risc0_zkvm::guest::env;

// Guest code:
// This is the portion of the code that will be proven
pub fn main() {
    let compliance_witness: ComplianceWitness<TREE_DEPTH> = env::read();

    let compliance_circuit: ComplianceCircuit<TREE_DEPTH> = ComplianceCircuit { compliance_witness };
    let consumed_logic_ref = compliance_circuit.get_consumed_resource_logic();
    let comsumed_cm = compliance_circuit.consumed_commitment();
    let nullifier = compliance_circuit.consumed_nullifier(&comsumed_cm);
    let created_logic_ref = compliance_circuit.get_created_resource_logic();
    let commitment = compliance_circuit.created_commitment();
    let merkle_root = compliance_circuit.merkle_tree_root(comsumed_cm);
    let delta = compliance_circuit.delta_commitment();

    let compliance_instance = ComplianceInstance {
        nullifier,
        commitment,
        consumed_logic_ref,
        created_logic_ref,
        merkle_root,
        delta
    };

    env::commit(&compliance_instance);
}
