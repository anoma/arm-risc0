use kudo_logic_witness::kudo_main_witness::{KudoMainWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: KudoMainWitness = env::read();

    // process constraints
    let instance = witness.constrain().unwrap();

    // write public output to the journal
    env::commit(&instance);
}
