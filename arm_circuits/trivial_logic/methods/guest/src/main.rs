use anoma_rm_risc0::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    #[cfg(feature = "evm")]
    {
        env::commit_slice(&instance.abi_encode());
    }

    #[cfg(not(feature = "evm"))]
    env::commit(&instance);
}
