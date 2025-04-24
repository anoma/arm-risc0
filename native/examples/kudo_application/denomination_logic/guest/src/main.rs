use kudo_core::denomination_logic_witness::DenominationLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: DenominationLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
