pub mod call;
pub mod types;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::primitives::{B256, U256,Bytes};
    use alloy::sol_types::SolType;
    use rand::random;
    use types::Resource;

    #[test]
    fn encode_resource() {
        let res = Resource {
            logicRef: B256::from(hex!(
                "1111111111111111111111111111111111111111111111111111111111111111"
            )),
            labelRef: B256::from(hex!(
                "2222222222222222222222222222222222222222222222222222222222222222"
            )),
            quantity: U256::from(12),
            valueRef: B256::from(U256::from(1)),
            ephemeral: true,
            nonce: U256::from_be_bytes(random::<[u8; 32]>()),
            nullifierKeyCommitment: B256::from(U256::from(0)),
            randSeed: U256::from(0),
        };
        
        let encoded: Vec<u8> = <Resource as SolType>::abi_encode(&res);
        println!("{}",Bytes::from(encoded));
    }
}
