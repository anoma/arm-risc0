pub mod call;
pub mod conversion;
pub mod types;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, B256, U256};
    use alloy::sol_types::SolType;
    use rand::random;
    use types::Resource;

    #[test]
    fn test_encode_resource() {
        let res = Resource {
            logicRef: B256::from_slice(&[0x11; 32]),
            labelRef: B256::from_slice(&[0x22; 32]),
            quantity: U256::from(12),
            valueRef: B256::from(U256::from(1)),
            ephemeral: true,
            nonce: U256::from_be_bytes(random::<[u8; 32]>()),
            nullifierKeyCommitment: B256::from(U256::from(0)),
            randSeed: U256::from(0),
        };

        let encoded: Vec<u8> = <Resource as SolType>::abi_encode(&res);
        println!("{}", Bytes::from(encoded));
    }
}
