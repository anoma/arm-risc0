use arm::resource_logic::LogicCircuit;
use arm::test_logic::TestLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TestLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}