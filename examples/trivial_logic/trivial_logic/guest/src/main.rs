use arm::resource_logic::{LogicCircuit, TrivialLogicWitness};
use risc0_zkvm::guest::env;

fn main() {
    let witness: TrivialLogicWitness = env::read();

    let instance = witness.constrain();

    use alloy_sol_types::{sol_data::*, SolType, SolValue};

    // Represent a Solidity type in rust
    type MySolType = FixedArray<Bool, 2>;

    let data = [true, false];

    // SolTypes expose their Solidity name :)
    assert_eq!(&MySolType::sol_type_name(), "bool[2]");

    // SolTypes are used to transform Rust into ABI blobs, and back.
    let encoded: Vec<u8> = MySolType::abi_encode(&data);
    let decoded: [bool; 2] = MySolType::abi_decode(&encoded).unwrap();
    assert_eq!(data, decoded);

    // This is more easily done with the `SolValue` trait:
    let encoded: Vec<u8> = data.abi_encode();
    let decoded: [bool; 2] = <[bool; 2]>::abi_decode(&encoded).unwrap();
    assert_eq!(data, decoded);

    {
        use alloy_primitives::U256;
        use alloy_sol_types::{sol, SolStruct};
        sol! {
            struct MyStruct {
                uint256 a;
                bytes32 b;
                address[] c;
            }
        }

        sol! {
            struct MyStruct2 {
                MyStruct a;
                bytes32 b;
                address[] c;
            }
        }

        // All structs generated with `sol!` implement `crate::SolType` &
        // `crate::SolStruct`. This means you get eip-712 signing for freeeeee
        let my_struct = MyStruct {
            a: U256::from(1),
            b: [0; 32].into(),
            c: vec![Default::default()],
        };

        // The `eip712_domain` macro lets you easily define an EIP-712 domain
        // object :)
        let my_domain = alloy_sol_types::eip712_domain!(
           name: "MyDomain",
           version: "1",
        );

        // Because all the hard work is done by the `sol!` macro, EIP-712 is as easy
        // as calling `eip712_signing_hash` with your domain
        let _signing_hash = my_struct.eip712_signing_hash(&my_domain);
    }
    env::commit(&instance);
}
