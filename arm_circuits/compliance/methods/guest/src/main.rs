use anoma_rm_risc0::compliance::ComplianceWitness;
use risc0_zkvm::guest::env;

pub fn main() {
    let compliance_witness: ComplianceWitness = env::read();

    let compliance_instance = compliance_witness.constrain().unwrap();

    #[cfg(feature = "bin")]
    {
        let output_bytes = bincode::serialize(&compliance_instance).unwrap();
        env::commit_slice(&output_bytes);
    }

    #[cfg(feature = "borsh")]
    {
        let output_bytes = borsh::to_vec(&compliance_instance).unwrap();
        env::commit_slice(&output_bytes);
    }

    #[cfg(not(any(feature = "bin", feature = "borsh")))]
    env::commit(&compliance_instance);
}
