//! Raw byte constants for verification keys.
use hex_literal::hex;

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex!("919e13001cd3319be5a5a7cb189203be083674acb3fff23d05aae9c3ed86314d");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex!("21fcc2fc2c07f9753405d3070f2488c67389f7d797b6f6e20a9f2529fe4a0bff");

/// Batch aggregation verification key bytes.
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex!("213b3f40d7c113c1a012072fcd791fa44bf5166a2300121630bd3228e2b00827");

/// Hash of the empty string - used for PADDING_LEAF and INITIAL_ROOT.
pub const EMPTY_HASH_BYTES: [u8; 32] =
    hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

/// Hash of the empty string as u32 words (little-endian).
/// Same value as EMPTY_HASH_BYTES, reinterpreted as [u32; 8].
pub const EMPTY_HASH_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee, 0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];
