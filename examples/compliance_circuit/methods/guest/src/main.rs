use arm::{compliance::ComplianceWitness, merkle_path::COMMITMENT_TREE_DEPTH};
use risc0_zkvm::guest::env;

// Guest code:
// This is the portion of the code that will be proven
pub fn main() {
    let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> = env::read();

    let compliance_instance = compliance_witness.constrain();

    env::commit(&compliance_instance);
}
