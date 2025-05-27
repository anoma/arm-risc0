use aarm_core::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain();

    // let instance = witness.test_constrain();

    env::commit(&instance);
}
