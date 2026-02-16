use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0_test_witness::TestLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TestLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}