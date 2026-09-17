//! ARM EVM gadgets for resource logics(applications).

use alloy_primitives::B256;
use alloy_sol_types::{sol, SolValue};
use anoma_rm_risc0::resource::Resource as ArmResource;

sol! {
    struct Resource {
        bytes32 logicRef;
        bytes32 labelRef;
        bytes32 valueRef;
        bytes32 nullifierKeyCommitment;
        bytes32 nonce;
        bytes32 randSeed;
        uint128 quantity;
        bool ephemeral;
    }
}

impl Resource {
    /// Encodes the Resource struct into a byte vector using ABI encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode_params()
    }

    /// Decodes a byte slice into a Resource struct using ABI decoding.
    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode_params(encoded).ok()
    }
}

impl From<ArmResource> for Resource {
    fn from(r: ArmResource) -> Self {
        Self {
            logicRef: B256::from_slice(r.logic_ref.as_bytes()),
            labelRef: B256::from_slice(r.label_ref.as_bytes()),
            quantity: r.quantity,
            valueRef: B256::from_slice(r.value_ref.as_bytes()),
            ephemeral: r.is_ephemeral,
            nonce: B256::from_slice(&r.nonce),
            nullifierKeyCommitment: B256::from_slice(r.nk_commitment.as_bytes()),
            randSeed: B256::from_slice(&r.rand_seed),
        }
    }
}

sol! {
    struct ForwarderCalldata {
        address untrustedForwarder;
        bytes input;
        bytes output;
        // The calls of these tags must run before this call.
        bytes32[] afterTags;
        // The calls of these tags must not run before this call.
        bytes32[] beforeTags;
    }
}

impl ForwarderCalldata {
    /// Creates a new ForwarderCalldata instance.
    pub fn new(untrusted_forwarder: &str, input: Vec<u8>, output: Vec<u8>) -> Self {
        // This is only used in circuits, just let it panic if the address is invalid
        let untrusted_forwarder_addr = untrusted_forwarder.parse().expect("Invalid address string");
        ForwarderCalldata {
            untrustedForwarder: untrusted_forwarder_addr,
            input: input.into(),
            output: output.into(),
            afterTags: Vec::new(),
            beforeTags: Vec::new(),
        }
    }

    /// Creates a new ForwarderCalldata instance from hex strings.
    pub fn from_hex(untrusted_forwarder: &str, input: &str, output: &str) -> Self {
        // This is only used in circuits, just let it panic if the address is invalid
        let untrusted_forwarder_addr = untrusted_forwarder.parse().expect("Invalid address string");
        ForwarderCalldata {
            untrustedForwarder: untrusted_forwarder_addr,
            input: hex::decode(input).expect("Invalid hex input").into(),
            output: hex::decode(output).expect("Invalid hex output").into(),
            afterTags: Vec::new(),
            beforeTags: Vec::new(),
        }
    }

    /// Creates a new ForwarderCalldata instance from byte slices.
    pub fn from_bytes(untrusted_forwarder: &[u8], input: Vec<u8>, output: Vec<u8>) -> Self {
        ForwarderCalldata {
            // This is only used in circuits, just let it panic if the address is invalid
            untrustedForwarder: untrusted_forwarder
                .try_into()
                .expect("Invalid address bytes"),
            input: input.into(),
            output: output.into(),
            afterTags: Vec::new(),
            beforeTags: Vec::new(),
        }
    }

    /// Constrains when this call runs relative to the calls of other resources. A tag in `after_tags` names a
    /// resource whose calls must have run already; a tag in `before_tags` names one whose calls must not have.
    pub fn with_ordering(mut self, after_tags: Vec<B256>, before_tags: Vec<B256>) -> Self {
        self.afterTags = after_tags;
        self.beforeTags = before_tags;
        self
    }

    /// Encodes the ForwarderCalldata struct into a byte vector using ABI encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode_params()
    }

    /// Decodes a byte slice into a ForwarderCalldata struct using ABI decoding.
    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode_params(encoded).ok()
    }
}

#[test]
fn forward_call_data_test() {
    // Example data
    let addr = hex::decode("ffffffffffffffffffffffffffffffffffffffff").unwrap();
    let input = hex::decode("ab").unwrap();
    let output = hex::decode("cd").unwrap();

    // Create instance
    let data = ForwarderCalldata::from_bytes(&addr, input, output);

    // abi encode
    let encoded_data = data.encode();
    println!("encode: {:?}", hex::encode(&encoded_data));
    println!("len: {}", encoded_data.len());
    let decoded_data = ForwarderCalldata::decode(&encoded_data).unwrap();

    assert_eq!(data.untrustedForwarder, decoded_data.untrustedForwarder);
    assert_eq!(data.input, decoded_data.input);
    assert_eq!(data.output, decoded_data.output);
    assert!(decoded_data.afterTags.is_empty());
    assert!(decoded_data.beforeTags.is_empty());
}

#[test]
fn forward_call_data_carries_the_ordering_constraints() {
    let addr = hex::decode("ffffffffffffffffffffffffffffffffffffffff").unwrap();
    let after = B256::repeat_byte(0xaa);
    let before = B256::repeat_byte(0xbb);

    let data = ForwarderCalldata::from_bytes(&addr, vec![0xab], vec![0xcd])
        .with_ordering(vec![after], vec![before]);

    let decoded_data = ForwarderCalldata::decode(&data.encode()).unwrap();

    assert_eq!(decoded_data.afterTags, vec![after]);
    assert_eq!(decoded_data.beforeTags, vec![before]);
}

#[test]
fn evm_resource_test() {
    let arm_resource = ArmResource::default();
    let evm_resource: Resource = arm_resource.into();
    let encoded_resource = evm_resource.encode();
    let decoded_resource = Resource::decode(&encoded_resource).unwrap();
    assert_eq!(
        arm_resource.logic_ref.as_bytes(),
        decoded_resource.logicRef.as_slice()
    );
    assert_eq!(
        arm_resource.label_ref.as_bytes(),
        decoded_resource.labelRef.as_slice()
    );
    assert_eq!(
        arm_resource.value_ref.as_bytes(),
        decoded_resource.valueRef.as_slice()
    );
    assert_eq!(arm_resource.nonce, decoded_resource.nonce.as_slice());
    assert_eq!(arm_resource.rand_seed, decoded_resource.randSeed.as_slice());
    assert_eq!(arm_resource.is_ephemeral, decoded_resource.ephemeral);
    assert_eq!(arm_resource.quantity, decoded_resource.quantity);
    assert_eq!(
        arm_resource.nk_commitment.as_bytes(),
        decoded_resource.nullifierKeyCommitment.as_slice()
    );
}
