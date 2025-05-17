use receive_core::{SimpleReceiveWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: SimpleReceiveWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
