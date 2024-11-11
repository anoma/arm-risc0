use aarm_core::{
    compliance::{ComplianceCircuit, ComplianceInstance, ComplianceWitness},
    constants::TREE_DEPTH,
    utils::GenericEnv
};
use risc0_zkvm::guest::env;
use bincode;

// Guest code: 
// This is the portion of the code that will be proven
pub fn main() {
    // 
    let generic_env: GenericEnv = env::read();
    let compliance_witness: ComplianceWitness<TREE_DEPTH> = bincode::deserialize(&generic_env.data)
        .expect("Failed to deserialize environment data");


    let compliance_circuit: ComplianceCircuit<TREE_DEPTH> = ComplianceCircuit { compliance_witness };
    let input_resource_logic = compliance_circuit.input_resource_logic();
    let input_nf = compliance_circuit.input_resource_nf();
    let input_cm = compliance_circuit.input_resource_cm();        
    let output_resource_logic = compliance_circuit.output_resource_logic();
    let output_cm = compliance_circuit.output_resource_cm();        
    let merkle_root = compliance_circuit.merkle_tree_root(input_cm);
    let delta = compliance_circuit.delta_commitment();

    let compliance_instance = ComplianceInstance {
        input_nf, 
        output_cm, 
        input_resource_logic, 
        output_resource_logic, 
        merkle_root, 
        delta
    };

    env::commit(&compliance_instance);
}
