use anoma_rm_risc0::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
