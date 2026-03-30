use anoma_rm_risc0::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let mut instance = witness.constrain().unwrap();
    instance.compute_and_set_app_data_hash();

    env::commit(&instance);
}
