use aarm_core::{Compliance, TREE_DEPTH};
use risc0_zkvm::guest::env;

// Guest code: 
// This is the portion of the code that will be proven
pub fn main() {
    // 
    let compliance_circuit: Compliance<TREE_DEPTH> = env::read();

    let input_resource_logic = compliance_circuit.input_resource_logic();
    let input_nf = compliance_circuit.input_resource_nf();
    let input_cm = compliance_circuit.input_resource_cm();        
    let output_resource_logic = compliance_circuit.output_resource_logic();
    let output_cm = compliance_circuit.output_resource_cm();        
    let merkle_root = compliance_circuit.merkle_tree_root(input_cm);
    let delta = compliance_circuit.delta_commitment();

    env::commit(&(input_resource_logic, input_nf, output_resource_logic, output_cm, merkle_root, delta));
}