use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;

use anoma_rm_risc0::compliance::ComplianceInstanceWords;

///  The batch aggregation circuit.
fn main() {
    // Read the inputs.
    let compliance_instances: Vec<ComplianceInstanceWords> = env::read();
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
        env::verify(compliance_key, &ci.u32_words).unwrap();
    }
    for i in 0..logic_instances.len() {
        env::verify(logic_keys[i], &logic_instances[i]).unwrap();
    }

    // The output.
    #[cfg(feature = "evm")]
    {
        use anoma_rm_risc0::abi::{
            encode_bytes, encode_bytes32, encode_dynamic_array, encode_static_array, encode_tuple,
            AbiToken,
        };

        // compliance_instances: bytes[] (each element is 224 raw bytes)
        let ci_encoded: Vec<Vec<u8>> = compliance_instances
            .iter()
            .map(|ci| encode_bytes(&ci.abi_encode()))
            .collect();

        // logic_instances: bytes[] (each element is raw journal bytes)
        let li_encoded: Vec<Vec<u8>> = logic_instances
            .iter()
            .map(|li| {
                let bytes: Vec<u8> = li.iter().flat_map(|w| w.to_le_bytes()).collect();
                encode_bytes(&bytes)
            })
            .collect();

        // logic_keys: bytes32[]
        let lk_items: Vec<[u8; 32]> = logic_keys
            .iter()
            .map(|k| encode_bytes32(k.as_bytes()))
            .collect();

        let output_bytes = encode_tuple(&[
            AbiToken::Dynamic(encode_dynamic_array(&ci_encoded)),
            AbiToken::Word(encode_bytes32(compliance_key.as_bytes())),
            AbiToken::Dynamic(encode_dynamic_array(&li_encoded)),
            AbiToken::Dynamic(encode_static_array(&lk_items)),
        ]);

        env::commit_slice(&output_bytes);
    }

    #[cfg(not(feature = "evm"))]
    {
        let output = (
            compliance_instances,
            compliance_key,
            logic_instances,
            logic_keys,
        );

        #[cfg(feature = "bin")]
        {
            let output_bytes = bincode::serialize(&output).unwrap();
            env::commit_slice(&output_bytes);
        }

        #[cfg(feature = "borsh")]
        {
            let output_bytes = borsh::to_vec(&output).unwrap();
            env::commit_slice(&output_bytes);
        }

        #[cfg(not(any(feature = "bin", feature = "borsh")))]
        env::commit(&output);
    }
}
