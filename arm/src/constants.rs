//! Constants for compliance and padding logic proving and verification keys.

/// The hash of an empty string, used as the initial Merkle tree root and padding leaf.
/// Hex: cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06
pub const EMPTY_HASH_WORDS: [u32; 8] = [
    0x832f1dcc, 0x7adb4584, 0xf91d43ec, 0x1f878aee,
    0x5eaae740, 0x56c04f06, 0xc6f83e63, 0x067bab0f,
];

/// Compliance verification key bytes.
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex_literal::hex!("1176e7f038c55009f369e2eafd1dd9bc5b51a6f5fc6369cc9f54779258f898fc");

/// Padding logic verification key bytes.
pub const PADDING_LOGIC_VK_BYTES: [u8; 32] =
    hex_literal::hex!("f48e335148e57f9cad071feb845588bf0ef43f55784f2e184439b152904446be");

/// Batch aggregation verification key bytes.
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex_literal::hex!("0235fd42c773897d07063ad9515723e2ea8d7f54a786b230b5395fd73071d8d3");

/// Sequential aggregation verification key bytes.
pub const SEQUENTIAL_AGGREGATION_VK_BYTES: [u8; 32] =
    hex_literal::hex!("378bebfe9a8e136e28d309f582474ab02da3c8ef005e7b3c88727c563dfd2752");

#[cfg(feature = "zkvm")]
lazy_static::lazy_static! {
    /// Compliance verification key as a Digest.
    pub static ref COMPLIANCE_VK: crate::Digest =
        crate::Digest::new(bytemuck::cast(COMPLIANCE_VK_BYTES));

    /// Padding logic verification key as a Digest.
    pub static ref PADDING_LOGIC_VK: crate::Digest =
        crate::Digest::new(bytemuck::cast(PADDING_LOGIC_VK_BYTES));
}

/// Compliance proving key / compliance guest ELF binary.
#[cfg(feature = "zkvm")]
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");

/// Padding logic proving key / padding logic guest ELF binary.
#[cfg(feature = "zkvm")]
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");
