use anoma_rm_risc0::compliance::ComplianceWitness;
use risc0_zkvm::guest::env;

// Guest code:
// This is the portion of the code that will be proven
pub fn main() {
    let compliance_witness: ComplianceWitness = env::read();

    let compliance_instance = compliance_witness.constrain().unwrap();

    env::commit(&compliance_instance);
}
