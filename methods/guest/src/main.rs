use aarm_core::Compliance;
use risc0_zkvm::guest::env;

// Guest code: 
// This is the portion of the code that will be proven
pub fn main() {
    // 
    let compliance_circuit: Compliance<16> = env::read();

    let input_nf = compliance_circuit.input_resource_nf();
    let output_cm = compliance_circuit.output_resource_cm();        
    let merkle_root = compliance_circuit.merkle_tree_root(output_cm);
    let delta = compliance_circuit.delta_commitment();

    env::commit(&(input_nf, output_cm, merkle_root, delta));
}