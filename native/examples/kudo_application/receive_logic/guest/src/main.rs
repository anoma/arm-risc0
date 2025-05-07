use kudo_core::receive_logic_witness::ReceiveLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: ReceiveLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
