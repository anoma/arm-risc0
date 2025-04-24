use kudo_core::kudo_logic_witness::KudoLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: KudoLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
