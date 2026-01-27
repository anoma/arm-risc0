use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0_test_witness::TestLogicWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TestLogicWitness = env::read();

    let instance = witness.constrain().unwrap();

    #[cfg(feature = "bin")]
    {
        let instance_bytes = bincode::serialize(&instance).unwrap();
        env::commit_slice(&instance_bytes);
    }

    #[cfg(feature = "borsh")]
    {
        let instance_bytes = borsh::to_vec(&instance).unwrap();
        env::commit_slice(&instance_bytes);
    }

    #[cfg(not(any(feature = "bin", feature = "borsh")))]
    env::commit(&instance);
}
