use crate::resource::Resource as ArmResource;
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolValue};

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
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode(encoded).ok()
    }

    pub fn encode_with_nk(&self, nk: &[u8]) -> Vec<u8> {
        (self.clone(), B256::from_slice(nk)).abi_encode()
    }

    pub fn decode_with_nk(encoded: &[u8]) -> Option<(Self, Vec<u8>)> {
        let (resource, nk) = <(Resource, B256)>::abi_decode(encoded).ok()?;
        Some((resource, nk.to_vec()))
    }
}

impl From<ArmResource> for Resource {
    fn from(r: ArmResource) -> Self {
        Self {
            logicRef: B256::from_slice(&r.logic_ref),
            labelRef: B256::from_slice(&r.label_ref),
            quantity: r.quantity,
            valueRef: B256::from_slice(&r.value_ref),
            ephemeral: r.is_ephemeral,
            nonce: B256::from_slice(&r.nonce),
            nullifierKeyCommitment: B256::from_slice(r.nk_commitment.inner()),
            randSeed: B256::from_slice(&r.rand_seed),
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

    pub fn from_bytes(untrusted_forwarder: &[u8], input: Vec<u8>, output: Vec<u8>) -> Self {
        ForwarderCalldata {
            untrustedForwarder: untrusted_forwarder
                .try_into()
                .expect("Invalid address bytes"),
            input: input.into(),
            output: output.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(encoded: &[u8]) -> Option<Self> {
        Self::abi_decode(encoded).ok()
    }
}

sol! {
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    enum CallType {
        Transfer, // burn
        TransferFrom, // mint
        PermitWitnessTransferFrom // mint with permit info
    }

    /// @notice The token and amount details for a transfer signed in the permit transfer signature
    struct TokenPermissions {
        // ERC20 token address
        address token;
        // the maximum amount that can be spent
        uint256 amount;
    }

    /// @notice The signed permit message for a single token transfer
    struct PermitTransferFrom {
        TokenPermissions permitted;
        // a unique value for every token owner's signature to prevent signature replays
        // In permit2, this is a uint256
        bytes32 nonce;
        // deadline on the permit signature
        // In permit2, this is a uint256
        bytes32 deadline;
    }
}

impl PermitTransferFrom {
    pub fn from_bytes(token: &[u8], amount: u128, nonce: &[u8], deadline: &[u8]) -> Self {
        let token_addr: Address = token.try_into().expect("Invalid address bytes");
        PermitTransferFrom {
            permitted: TokenPermissions {
                token: token_addr,
                amount: U256::from(amount),
            },
            nonce: B256::from_slice(nonce),
            deadline: B256::from_slice(deadline),
        }
    }
}

pub fn encode_transfer(token: &[u8], to: &[u8], value: u128) -> Vec<u8> {
    // Encode as (CallType, token, to, value)
    let token: Address = token.try_into().expect("Invalid address bytes");
    let to: Address = to.try_into().expect("Invalid address bytes");
    let value = U256::from(value);
    (CallType::Transfer, token, to, value).abi_encode_params()
}

pub fn encode_transfer_from(token: &[u8], from: &[u8], value: u128) -> Vec<u8> {
    // Encode as (CallType, token, from, value)
    let token_addr: Address = token.try_into().expect("Invalid address bytes");
    let from_addr: Address = from.try_into().expect("Invalid address bytes");
    let value = U256::from(value);
    (CallType::TransferFrom, token_addr, from_addr, value).abi_encode_params()
}

pub fn encode_permit_witness_transfer_from(
    from: &[u8],
    permit: PermitTransferFrom,
    witness: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let from: Address = from.try_into().expect("Invalid address bytes");
    (
        CallType::PermitWitnessTransferFrom,
        from,
        permit,
        B256::from_slice(witness),
        signature,
    )
        .abi_encode_params()
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
    assert_eq!(arm_resource.nonce, decoded_resource.nonce.as_slice());
    assert_eq!(arm_resource.rand_seed, decoded_resource.randSeed.as_slice());
    assert_eq!(arm_resource.is_ephemeral, decoded_resource.ephemeral);
    assert_eq!(arm_resource.quantity, decoded_resource.quantity);
    assert_eq!(
        arm_resource.nk_commitment.inner(),
        decoded_resource.nullifierKeyCommitment.as_slice()
    );
}

#[test]
fn encode_permit_witness_transfer_from_test() {
    let token = hex::decode("2222222222222222222222222222222222222222").unwrap();
    let from = hex::decode("3333333333333333333333333333333333333333").unwrap();
    let value = 1000u128;
    let permit = PermitTransferFrom::from_bytes(&token, value, &vec![1u8; 32], &vec![2u8; 32]);
    let witness = vec![3u8; 32];
    let signature = vec![4u8; 65];

    let encoded = encode_permit_witness_transfer_from(&from, permit, &witness, &signature);
    println!("encode: {:?}", hex::encode(&encoded));
    println!("len: {}", encoded.len());
}
