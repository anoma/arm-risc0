//! Raw byte constants for verification keys.
use hex_literal::hex;

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex!("58a43fde97c103d5d947702f71c98fe353ba697b33c522e6871a039b8c1552cf");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex!("3637b96e144c59df101e5e11e047f2fc1f982c1d697d818d5b42c6130b0e39aa");

/// Batch aggregation verification key bytes.
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex!("a6efc4982685e2269e6026723374c5f29ce6a65e9683cb4b33f19a9c56a9ff27");

/// Hash of the empty string - used for PADDING_LEAF and INITIAL_ROOT.
pub const EMPTY_HASH_BYTES: [u8; 32] =
    hex!("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06");

/// Hash of the empty string as u32 words (little-endian).
/// Same value as EMPTY_HASH_BYTES, reinterpreted as [u32; 8].
pub const EMPTY_HASH_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee, 0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];
