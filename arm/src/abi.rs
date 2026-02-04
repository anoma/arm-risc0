//! Solidity ABI encoding helpers for EVM compatibility.
//!
//! Implements encoding according to the Solidity ABI specification.
//! No external dependencies — pure byte manipulation using `bytemuck`.

/// Represents a field in an ABI-encoded tuple.
pub enum AbiToken {
    /// A static value (bytes32, bool, uint32, etc.), exactly 32 bytes.
    Word([u8; 32]),
    /// A dynamic value (arrays, bytes, nested structs), pre-encoded.
    Dynamic(Vec<u8>),
}

/// Encodes a tuple of ABI tokens according to the Solidity ABI spec.
///
/// Static fields are placed inline in the head. Dynamic fields get an offset
/// pointer in the head, with the actual data appended in the tail.
/// Offsets are relative to the start of the tuple encoding.
pub fn encode_tuple(tokens: &[AbiToken]) -> Vec<u8> {
    let head_size = tokens.len() * 32;
    let mut head = Vec::with_capacity(head_size);
    let mut tail = Vec::new();

    for token in tokens {
        match token {
            AbiToken::Word(word) => {
                head.extend_from_slice(word);
            }
            AbiToken::Dynamic(data) => {
                let offset = head_size + tail.len();
                head.extend_from_slice(&encode_uint256_from_usize(offset));
                tail.extend_from_slice(data);
            }
        }
    }

    head.extend(tail);
    head
}

/// Copies up to 32 bytes into a `bytes32` word, zero-padding on the right.
///
/// Panics if `data` is longer than 32 bytes.
pub fn encode_bytes32(data: &[u8]) -> [u8; 32] {
    assert!(data.len() <= 32, "bytes32 data exceeds 32 bytes");
    let mut word = [0u8; 32];
    word[..data.len()].copy_from_slice(data);
    word
}

/// Encodes a boolean as a 32-byte ABI word (left-padded, big-endian).
pub fn encode_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value as u8;
    word
}

/// Encodes a `u32` as a 32-byte ABI word (big-endian, left-padded).
pub fn encode_uint32(value: u32) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[28..32].copy_from_slice(&value.to_be_bytes());
    word
}

/// Encodes a `usize` as a `uint256` ABI word (big-endian, left-padded).
pub fn encode_uint256_from_usize(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

/// Encodes an array of static 32-byte items.
///
/// Layout: `length (uint256) || item_0 || item_1 || ...`
pub fn encode_static_array(items: &[[u8; 32]]) -> Vec<u8> {
    let mut result = Vec::with_capacity(32 + items.len() * 32);
    result.extend_from_slice(&encode_uint256_from_usize(items.len()));
    for item in items {
        result.extend_from_slice(item);
    }
    result
}

/// Encodes an array of dynamic items (each item already ABI-encoded).
///
/// Layout: `length (uint256) || offset_0 || offset_1 || ... || item_0_data || item_1_data || ...`
///
/// Offsets are relative to the start of the element area (right after the length word).
pub fn encode_dynamic_array(items: &[Vec<u8>]) -> Vec<u8> {
    let k = items.len();
    let mut result = Vec::new();
    result.extend_from_slice(&encode_uint256_from_usize(k));

    // Offsets area: k slots, each 32 bytes
    let offsets_size = k * 32;
    let mut current_offset = offsets_size;

    // Write offset pointers
    for item in items {
        result.extend_from_slice(&encode_uint256_from_usize(current_offset));
        current_offset += item.len();
    }

    // Write item data
    for item in items {
        result.extend_from_slice(item);
    }

    result
}

/// Encodes raw bytes as the Solidity `bytes` type.
///
/// Layout: `length (uint256) || data || zero-padding to 32-byte boundary`
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let padding = (32 - (data.len() % 32)) % 32;
    let mut result = Vec::with_capacity(32 + data.len() + padding);
    result.extend_from_slice(&encode_uint256_from_usize(data.len()));
    result.extend_from_slice(data);
    result.resize(result.len() + padding, 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bool() {
        let t = encode_bool(true);
        assert_eq!(t[31], 1);
        assert!(t[..31].iter().all(|&b| b == 0));

        let f = encode_bool(false);
        assert!(f.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_uint32() {
        let encoded = encode_uint32(0x12345678);
        assert!(encoded[..28].iter().all(|&b| b == 0));
        assert_eq!(&encoded[28..32], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_encode_uint256_from_usize() {
        let encoded = encode_uint256_from_usize(256);
        assert!(encoded[..30].iter().all(|&b| b == 0));
        assert_eq!(&encoded[30..32], &[0x01, 0x00]);
    }

    #[test]
    fn test_encode_bytes32() {
        let data = [0xABu8; 32];
        let encoded = encode_bytes32(&data);
        assert_eq!(encoded, data);
    }

    #[test]
    fn test_encode_bytes32_short_input() {
        let data = [0xABu8; 16];
        let encoded = encode_bytes32(&data);
        assert_eq!(&encoded[..16], &data);
        assert!(encoded[16..].iter().all(|&b| b == 0));
    }

    #[test]
    #[should_panic(expected = "bytes32 data exceeds 32 bytes")]
    fn test_encode_bytes32_too_long() {
        encode_bytes32(&[0u8; 33]);
    }

    #[test]
    fn test_encode_bytes_padding() {
        // 5 bytes of data should be padded to 32
        let data = [1, 2, 3, 4, 5];
        let encoded = encode_bytes(&data);
        // length word (32) + data (5) + padding (27) = 64
        assert_eq!(encoded.len(), 64);
        assert_eq!(
            &encoded[..32],
            &encode_uint256_from_usize(5)
        );
        assert_eq!(&encoded[32..37], &data);
        assert!(encoded[37..64].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_bytes_exact_multiple() {
        // 32 bytes of data needs no padding
        let data = [0xFFu8; 32];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded.len(), 64);
    }

    #[test]
    fn test_encode_bytes_empty() {
        let encoded = encode_bytes(&[]);
        assert_eq!(encoded.len(), 32); // just the length word
        assert_eq!(encoded, encode_uint256_from_usize(0));
    }

    #[test]
    fn test_encode_static_array() {
        let items = [
            encode_uint32(1),
            encode_uint32(2),
            encode_uint32(3),
        ];
        let encoded = encode_static_array(&items);
        // length (32) + 3 items (96) = 128
        assert_eq!(encoded.len(), 128);
        assert_eq!(&encoded[..32], &encode_uint256_from_usize(3));
        assert_eq!(&encoded[32..64], &encode_uint32(1));
        assert_eq!(&encoded[64..96], &encode_uint32(2));
        assert_eq!(&encoded[96..128], &encode_uint32(3));
    }

    #[test]
    fn test_encode_dynamic_array() {
        // Two dynamic items of different sizes
        let item0 = encode_bytes(&[0xAA; 5]); // 64 bytes
        let item1 = encode_bytes(&[0xBB; 33]); // 96 bytes
        let encoded = encode_dynamic_array(&[item0.clone(), item1.clone()]);

        // length (32) + 2 offsets (64) + item0 (64) + item1 (96) = 256
        assert_eq!(encoded.len(), 256);

        // length = 2
        assert_eq!(&encoded[..32], &encode_uint256_from_usize(2));

        // offset_0 = 64 (2 * 32, start of data area relative to element area)
        assert_eq!(&encoded[32..64], &encode_uint256_from_usize(64));
        // offset_1 = 64 + 64 = 128
        assert_eq!(&encoded[64..96], &encode_uint256_from_usize(128));

        // item data
        assert_eq!(&encoded[96..160], &item0);
        assert_eq!(&encoded[160..256], &item1);
    }

    #[test]
    fn test_encode_tuple_all_static() {
        let tokens = [
            AbiToken::Word(encode_uint32(42)),
            AbiToken::Word(encode_bool(true)),
        ];
        let encoded = encode_tuple(&tokens);
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[..32], &encode_uint32(42));
        assert_eq!(&encoded[32..64], &encode_bool(true));
    }

    #[test]
    fn test_encode_tuple_with_dynamic() {
        let dynamic_data = encode_bytes(&[0xFF; 10]);
        let tokens = [
            AbiToken::Word(encode_uint32(1)),
            AbiToken::Dynamic(dynamic_data.clone()),
            AbiToken::Word(encode_bool(false)),
        ];
        let encoded = encode_tuple(&tokens);

        // head: 3 * 32 = 96 bytes
        // tail: dynamic_data.len() bytes
        let head_size = 96;
        assert_eq!(encoded.len(), head_size + dynamic_data.len());

        // First field: uint32(1)
        assert_eq!(&encoded[..32], &encode_uint32(1));
        // Second field: offset to dynamic data
        assert_eq!(&encoded[32..64], &encode_uint256_from_usize(head_size));
        // Third field: bool(false)
        assert_eq!(&encoded[64..96], &encode_bool(false));
        // Tail: the dynamic data
        assert_eq!(&encoded[96..], &dynamic_data);
    }

    #[test]
    fn test_encode_dynamic_array_empty() {
        let encoded = encode_dynamic_array(&[]);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, encode_uint256_from_usize(0));
    }
}

/// Roundtrip tests that decode our ABI output with `alloy-sol-types`.
#[cfg(all(test, any(feature = "compliance_circuit", feature = "aggregation_circuit")))]
mod roundtrip_tests {
    use crate::compliance::{ComplianceInstance, ComplianceInstanceWords};
    use crate::logic_instance::{AppData, ExpirableBlob, LogicInstance};
    use crate::Digest;
    use alloy_sol_types::{sol, SolType};

    sol! {
        struct SolComplianceInstance {
            bytes32 consumedNullifier;
            bytes32 consumedLogicRef;
            bytes32 consumedCommitmentTreeRoot;
            bytes32 createdCommitment;
            bytes32 createdLogicRef;
            bytes32 deltaX;
            bytes32 deltaY;
        }

        struct SolExpirableBlob {
            uint32[] blob;
            uint32 deletionCriterion;
        }

        struct SolAppData {
            SolExpirableBlob[] resourcePayload;
            SolExpirableBlob[] discoveryPayload;
            SolExpirableBlob[] externalPayload;
            SolExpirableBlob[] applicationPayload;
        }

        struct SolLogicInstance {
            bytes32 tag;
            bool isConsumed;
            bytes32 root;
            SolAppData appData;
        }
    }

    #[test]
    fn compliance_instance_abi_roundtrip() {
        let instance = ComplianceInstance {
            consumed_nullifier: Digest::new([1u32; 8]),
            consumed_logic_ref: Digest::new([2u32; 8]),
            consumed_commitment_tree_root: Digest::new([3u32; 8]),
            created_commitment: Digest::new([4u32; 8]),
            created_logic_ref: Digest::new([5u32; 8]),
            delta_x: [6u32; 8],
            delta_y: [7u32; 8],
        };

        let encoded = instance.abi_encode();
        assert_eq!(encoded.len(), 224, "ComplianceInstance should be 7 x 32 = 224 bytes");

        let decoded =
            <SolComplianceInstance as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode ComplianceInstance");

        assert_eq!(decoded.consumedNullifier.as_slice(), instance.consumed_nullifier.as_bytes());
        assert_eq!(decoded.consumedLogicRef.as_slice(), instance.consumed_logic_ref.as_bytes());
        assert_eq!(
            decoded.consumedCommitmentTreeRoot.as_slice(),
            instance.consumed_commitment_tree_root.as_bytes()
        );
        assert_eq!(decoded.createdCommitment.as_slice(), instance.created_commitment.as_bytes());
        assert_eq!(decoded.createdLogicRef.as_slice(), instance.created_logic_ref.as_bytes());
        assert_eq!(
            decoded.deltaX.as_slice(),
            bytemuck::cast_slice::<u32, u8>(&instance.delta_x)
        );
        assert_eq!(
            decoded.deltaY.as_slice(),
            bytemuck::cast_slice::<u32, u8>(&instance.delta_y)
        );
    }

    #[test]
    fn compliance_instance_words_abi_roundtrip() {
        // Build a ComplianceInstanceWords from known values
        let mut words = [0u32; 56];
        for (i, w) in words.iter_mut().enumerate() {
            *w = i as u32;
        }
        let ciw = ComplianceInstanceWords { u32_words: words };
        let encoded = ciw.abi_encode();
        assert_eq!(encoded.len(), 224);

        let decoded =
            <SolComplianceInstance as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode ComplianceInstanceWords");

        // First field (words 0..8) should match consumedNullifier
        assert_eq!(
            decoded.consumedNullifier.as_slice(),
            bytemuck::cast_slice::<u32, u8>(&words[0..8])
        );
    }

    #[test]
    fn expirable_blob_abi_roundtrip() {
        let blob = ExpirableBlob {
            blob: vec![100, 200, 300],
            deletion_criterion: 42,
        };

        let encoded = blob.abi_encode();

        let decoded =
            <SolExpirableBlob as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode ExpirableBlob");

        assert_eq!(decoded.blob, vec![100u32, 200, 300]);
        assert_eq!(decoded.deletionCriterion, 42);
    }

    #[test]
    fn expirable_blob_empty_blob_abi_roundtrip() {
        let blob = ExpirableBlob {
            blob: vec![],
            deletion_criterion: 0,
        };

        let encoded = blob.abi_encode();

        let decoded =
            <SolExpirableBlob as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode empty ExpirableBlob");

        assert!(decoded.blob.is_empty());
        assert_eq!(decoded.deletionCriterion, 0);
    }

    #[test]
    fn logic_instance_abi_roundtrip() {
        let instance = LogicInstance {
            tag: Digest::new([0xAAu32; 8]),
            is_consumed: true,
            root: Digest::new([0xBBu32; 8]),
            app_data: AppData {
                resource_payload: vec![
                    ExpirableBlob {
                        blob: vec![1, 2, 3],
                        deletion_criterion: 10,
                    },
                    ExpirableBlob {
                        blob: vec![4, 5],
                        deletion_criterion: 20,
                    },
                ],
                discovery_payload: vec![],
                external_payload: vec![ExpirableBlob {
                    blob: vec![],
                    deletion_criterion: 99,
                }],
                application_payload: vec![],
            },
        };

        let encoded = instance.abi_encode();

        let decoded =
            <SolLogicInstance as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode LogicInstance");

        assert_eq!(decoded.tag.as_slice(), instance.tag.as_bytes());
        assert_eq!(decoded.isConsumed, true);
        assert_eq!(decoded.root.as_slice(), instance.root.as_bytes());

        // Check resource_payload
        assert_eq!(decoded.appData.resourcePayload.len(), 2);
        assert_eq!(decoded.appData.resourcePayload[0].blob, vec![1u32, 2, 3]);
        assert_eq!(decoded.appData.resourcePayload[0].deletionCriterion, 10);
        assert_eq!(decoded.appData.resourcePayload[1].blob, vec![4u32, 5]);
        assert_eq!(decoded.appData.resourcePayload[1].deletionCriterion, 20);

        // Check empty arrays
        assert!(decoded.appData.discoveryPayload.is_empty());
        assert!(decoded.appData.applicationPayload.is_empty());

        // Check external_payload
        assert_eq!(decoded.appData.externalPayload.len(), 1);
        assert!(decoded.appData.externalPayload[0].blob.is_empty());
        assert_eq!(decoded.appData.externalPayload[0].deletionCriterion, 99);
    }

    #[test]
    fn logic_instance_empty_app_data_abi_roundtrip() {
        let instance = LogicInstance {
            tag: Digest::new([0xCCu32; 8]),
            is_consumed: false,
            root: Digest::new([0xDDu32; 8]),
            app_data: AppData::new(),
        };

        let encoded = instance.abi_encode();

        let decoded =
            <SolLogicInstance as SolType>::abi_decode_params(&encoded)
                .expect("alloy should decode LogicInstance with empty AppData");

        assert_eq!(decoded.tag.as_slice(), instance.tag.as_bytes());
        assert_eq!(decoded.isConsumed, false);
        assert_eq!(decoded.root.as_slice(), instance.root.as_bytes());
        assert!(decoded.appData.resourcePayload.is_empty());
        assert!(decoded.appData.discoveryPayload.is_empty());
        assert!(decoded.appData.externalPayload.is_empty());
        assert!(decoded.appData.applicationPayload.is_empty());
    }
}
