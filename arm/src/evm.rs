use crate::resource::Resource as ArmResource;
use alloy_primitives::{B256, U256};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
sol! {
    struct Resource {
        bytes32 logicRef;
        bytes32 labelRef;
        bytes32 valueRef;
        bytes32 nullifierKeyCommitment;
        uint256 quantity;
        uint256 nonce;
        uint256 randSeed;
        bool ephemeral;
    }
}

impl Resource {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode(encoded).ok()
    }
}

impl From<ArmResource> for Resource {
    fn from(r: ArmResource) -> Self {
        Self {
            logicRef: B256::from_slice(&r.logic_ref),
            labelRef: B256::from_slice(&r.label_ref),
            quantity: U256::from(r.quantity),
            valueRef: B256::from_slice(&r.value_ref),
            ephemeral: r.is_ephemeral,
            nonce: U256::from_le_slice(r.nonce.as_slice()),
            nullifierKeyCommitment: B256::from_slice(r.nk_commitment.inner()),
            randSeed: U256::from_le_slice(r.rand_seed.as_slice()),
        }
    }
}

sol! {
    struct ForwarderCalldata {
        address untrustedForwarder;
        bytes input;
        bytes output;
    }
}

impl ForwarderCalldata {
    pub fn new(untrusted_forwarder: &str, input: Vec<u8>, output: Vec<u8>) -> Self {
        let untrusted_forwarder_addr = untrusted_forwarder.parse().expect("Invalid address string");
        ForwarderCalldata {
            untrustedForwarder: untrusted_forwarder_addr,
            input: input.into(),
            output: output.into(),
        }
    }

    pub fn from_hex(untrusted_forwarder: &str, input: &str, output: &str) -> Self {
        let untrusted_forwarder_addr = untrusted_forwarder.parse().expect("Invalid address string");
        ForwarderCalldata {
            untrustedForwarder: untrusted_forwarder_addr,
            input: hex::decode(input).expect("Invalid hex input").into(),
            output: hex::decode(output).expect("Invalid hex output").into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode(encoded).ok()
    }
}

#[test]
fn forward_call_data_test() {
    // Example data
    let addr = "0x1111111111111111111111111111111111111111";
    let input = hex::decode("1122").unwrap();
    let output = hex::decode("aabbcc").unwrap();

    // Create instance
    let data = ForwarderCalldata::new(addr, input, output);
    let data_from_hex = ForwarderCalldata::from_hex(addr, "1122", "aabbcc");
    assert_eq!(data.input, data_from_hex.input);
    assert_eq!(data.output, data_from_hex.output);

    // abi encode
    let encoded_data = data.encode();
    let decoded_data = ForwarderCalldata::decode(&encoded_data).unwrap();

    assert_eq!(data.untrustedForwarder, decoded_data.untrustedForwarder);
    assert_eq!(data.input, decoded_data.input);
    assert_eq!(data.output, decoded_data.output);
}

#[test]
fn evm_resource_test() {
    let arm_resource = ArmResource::default();
    let evm_resource: Resource = arm_resource.clone().into();
    let encoded_resource = evm_resource.encode();
    let decoded_resource = Resource::decode(&encoded_resource).unwrap();
    assert_eq!(arm_resource.logic_ref, decoded_resource.logicRef.as_slice());
    assert_eq!(arm_resource.label_ref, decoded_resource.labelRef.as_slice());
    assert_eq!(arm_resource.value_ref, decoded_resource.valueRef.as_slice());
    assert_eq!(arm_resource.nonce, decoded_resource.nonce.as_le_slice());
    assert_eq!(
        arm_resource.rand_seed,
        decoded_resource.randSeed.as_le_slice()
    );
    assert_eq!(arm_resource.is_ephemeral, decoded_resource.ephemeral);
    assert_eq!(U256::from(arm_resource.quantity), decoded_resource.quantity);
    assert_eq!(
        arm_resource.nk_commitment.inner(),
        decoded_resource.nullifierKeyCommitment.as_slice()
    );
}
