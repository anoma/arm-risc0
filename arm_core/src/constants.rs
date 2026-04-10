//! Raw byte constants for verification keys.
use hex_literal::hex;

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex!("fe484ce955bd4b73bab8363bb9b959cee597a67e8691ee592a7558a624cf98c2");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex!("49d1fd1e4c01495f8e14c0b8f7cc4fe9594e6d595edddf8cf26cae2c419cd05b");

/// Batch aggregation verification key bytes.
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex!("e617093ac7e3028379b32715d3d478e91f8225898689caaa22c42ffc0cfabc7c");

/// Hash of the empty string - used for PADDING_LEAF and INITIAL_ROOT.
pub const EMPTY_HASH_BYTES: [u8; 32] =
    hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

/// Hash of the empty string as u32 words (little-endian).
/// Same value as EMPTY_HASH_BYTES, reinterpreted as [u32; 8].
pub const EMPTY_HASH_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee, 0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];
