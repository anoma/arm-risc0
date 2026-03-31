use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;

use anoma_rm_risc0::compliance::ComplianceInstanceWords;

/// The known compliance circuit verification key.
const COMPLIANCE_VK: Digest =
    Digest::from_bytes(arm_core::constants::COMPLIANCE_VK_BYTES);

///  The batch aggregation circuit.
fn main() {
    // Read the inputs.
    let compliance_instances: Vec<ComplianceInstanceWords> = env::read();
    let compliance_key: Digest = env::read();
    let logic_instances: Vec<Vec<u32>> = env::read();
    let logic_keys: Vec<Digest> = env::read();

    // The compliance VK is a known constant. Reject if the prover provides
    // a different value — defense-in-depth against journal manipulation.
    assert_eq!(
        compliance_key, COMPLIANCE_VK,
        "compliance key must match the known compliance circuit VK"
    );

    assert_eq!(
        logic_instances.len(),
        logic_keys.len(),
        "Mismatched logic instances and keys lengths"
    );

    // Verify the proofs.
    for ci in compliance_instances.iter() {
        env::verify(compliance_key, &ci.u32_words).unwrap();
    }
    for i in 0..logic_instances.len() {
        env::verify(logic_keys[i], &logic_instances[i]).unwrap();
    }

    // The output.
    env::commit(&(
        compliance_instances,
        compliance_key,
        logic_instances,
        logic_keys,
    ));
}
