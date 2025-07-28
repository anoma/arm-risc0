use kudo_logic_witness::simple_denomination_witness::{SimpleDenominationLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let witness: SimpleDenominationLogicWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}
