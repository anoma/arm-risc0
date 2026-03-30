use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0_test_witness::TestLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TestLogicWitness = env::read();

    let mut instance = witness.constrain().unwrap();
    instance.compute_and_set_app_data_hash();

    env::commit(&instance);
}