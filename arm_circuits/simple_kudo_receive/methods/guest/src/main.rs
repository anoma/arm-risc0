use kudo_logic_witness::simple_receive_witness::{SimpleReceiveLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: SimpleReceiveLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
