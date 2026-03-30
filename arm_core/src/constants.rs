//! Raw byte constants for verification keys.
use hex_literal::hex;

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex!("c98c686cda02753e78b423eeebf98f9b4d5251c5b01e4c98fcf9e7abeb7038d4");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex!("14804f506f4d332fb7e3b5ea024909bf81ffa13c9f91c4e2ca2c352c17575f69");

/// Batch aggregation verification key bytes.
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex!("df441ff50f7748c05f154a7aa539a6a77dcade1dba8a8f29d2187e3e355eb4f9");

/// Hash of the empty string - used for PADDING_LEAF and INITIAL_ROOT.
pub const EMPTY_HASH_BYTES: [u8; 32] =
    hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

/// Hash of the empty string as u32 words (little-endian).
/// Same value as EMPTY_HASH_BYTES, reinterpreted as [u32; 8].
pub const EMPTY_HASH_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee, 0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];
