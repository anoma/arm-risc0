use anoma_rm_risc0::resource_logic::{TrivialLogicWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    #[cfg(feature = "bin")]
    {
        let output_bytes = bincode::serialize(&instance).unwrap();
        env::commit_slice(&output_bytes);
    }

    #[cfg(feature = "borsh")]
    {
        let output_bytes = borsh::to_vec(&instance).unwrap();
        env::commit_slice(&output_bytes);
    }

    #[cfg(not(any(feature = "bin", feature = "borsh")))]
    env::commit(&instance);
}
