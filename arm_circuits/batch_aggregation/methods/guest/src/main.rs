use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;

/// The batch aggregation circuit.
fn main() {
    // Read the inputs.
    let compliance_instances: Vec<Vec<u32>> = env::read();
    let compliance_key: Digest = env::read();
    let logic_instances: Vec<Vec<u32>> = env::read();
    let logic_keys: Vec<Digest> = env::read();

    assert_eq!(
        logic_instances.len(),
        logic_keys.len(),
        "Mismatched logic instances and keys lengths"
    );

    // Verify the proofs.
    for ci in compliance_instances.iter() {
        env::verify(compliance_key, &ci).unwrap();
    }
    for i in 0..logic_instances.len() {
        env::verify(logic_keys[i], &logic_instances[i]).unwrap();
    }

    // Commit the output using the serialization selected at compile time.
    #[cfg(feature = "borsh")]
    {
        use borsh::BorshSerialize;

        #[derive(BorshSerialize)]
        struct AggregationOutput {
            compliance_instances: Vec<Vec<u32>>,
            compliance_key: [u32; 8],
            logic_instances: Vec<Vec<u32>>,
            logic_keys: Vec<[u32; 8]>,
        }

        let output = AggregationOutput {
            compliance_instances,
            compliance_key: *compliance_key.as_ref(),
            logic_instances,
            logic_keys: logic_keys.iter().map(|k| *k.as_ref()).collect(),
        };
        env::commit_slice(&borsh::to_vec(&output).unwrap());
    }

    #[cfg(feature = "evm")]
    {
        use alloy_sol_types::{sol_data, SolType};

        type AggOutputType = (
            sol_data::Array<sol_data::Array<sol_data::Uint<32>>>,
            sol_data::FixedBytes<32>,
            sol_data::Array<sol_data::Array<sol_data::Uint<32>>>,
            sol_data::Array<sol_data::FixedBytes<32>>,
        );

        let compliance_key_bytes: [u8; 32] = compliance_key.as_bytes().try_into().unwrap();
        let logic_keys_bytes: Vec<[u8; 32]> =
            logic_keys.iter().map(|k| k.as_bytes().try_into().unwrap()).collect();

        let encoded = AggOutputType::abi_encode_params(&(
            compliance_instances,
            compliance_key_bytes,
            logic_instances,
            logic_keys_bytes,
        ));
        env::commit_slice(&encoded);
    }

    // Default: risc0 native (serde) encoding.
    #[cfg(not(any(feature = "borsh", feature = "evm")))]
    env::commit(&(
        compliance_instances,
        compliance_key,
        logic_instances,
        logic_keys,
    ));
}
