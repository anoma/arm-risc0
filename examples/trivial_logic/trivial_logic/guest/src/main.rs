use aarm_core::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain();

    env::commit(&instance);
}
