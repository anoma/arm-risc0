use arm::resource_logic::LogicCircuit;
use simple_transfer_witness::SimpleTransferWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: SimpleTransferWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
