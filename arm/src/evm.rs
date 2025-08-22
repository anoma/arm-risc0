// use alloy_primitives::address;
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;

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
fn forward_call_data() {
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
