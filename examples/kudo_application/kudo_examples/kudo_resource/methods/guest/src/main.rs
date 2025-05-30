use kudo_resource_core::{KudoResourceLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: KudoResourceLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
