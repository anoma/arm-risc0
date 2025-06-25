use risc0_zkvm::guest::env;
use counter::{CounterWitness, LogicCircuit};

fn main() {
    // read the input
    let witness: CounterWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
