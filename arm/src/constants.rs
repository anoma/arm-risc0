// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_pk.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/padding_logic_pk.bin");

// compliance verification key / compliance image id
pub const COMPLIANCE_VK: &[u8; 32] = &[
    131, 139, 251, 125, 224, 45, 29, 63, 235, 117, 6, 44, 89, 168, 194, 40, 160, 163, 214, 149,
    113, 231, 229, 246, 255, 51, 247, 116, 26, 125, 129, 56,
];

// Padding logic verification key / padding logic image id
pub const PADDING_LOGIC_VK: &[u8; 32] = &[
    19, 97, 29, 167, 105, 176, 190, 224, 230, 169, 137, 143, 90, 210, 176, 192, 2, 215, 191, 183,
    42, 243, 127, 105, 6, 188, 151, 12, 100, 187, 118, 6,
];
