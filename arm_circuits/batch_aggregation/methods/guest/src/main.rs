use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;

use arm::compliance::CIWords;

///  The batch aggregation circuit.
fn main() {
    // Read the inputs.
    let compliance_instances: Vec<CIWords> = env::read();
    let compliance_key: Digest = env::read();
    let logic_instances: Vec<Vec<u32>> = env::read();
    let logic_keys: Vec<Digest> = env::read(); // Assume same length as `logic_instances`. Else will panic.

    // Verify the proofs.
    for ci in compliance_instances.iter() {
        env::verify(compliance_key, ci.get_words_as_ref()).unwrap();
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
