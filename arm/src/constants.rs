// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_pk.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/padding_logic_pk.bin");

// compliance verification key / compliance image id
pub const COMPLIANCE_VK: &[u8; 32] = &[
    249, 49, 216, 207, 16, 60, 39, 4, 62, 82, 155, 56, 28, 212, 10, 232, 253, 237, 8, 204, 234,
    243, 245, 31, 208, 117, 188, 0, 1, 104, 79, 215,
];

// Padding logic verification key / padding logic image id
pub const PADDING_LOGIC_VK: &[u8; 32] = &[
    19, 97, 29, 167, 105, 176, 190, 224, 230, 169, 137, 143, 90, 210, 176, 192, 2, 215, 191, 183,
    42, 243, 127, 105, 6, 188, 151, 12, 100, 187, 118, 6,
];
