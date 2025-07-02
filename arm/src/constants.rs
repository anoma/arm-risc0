// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_pk.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/padding_logic_pk.bin");

// compliance verification key / compliance image id
pub const COMPLIANCE_VK: &[u8; 32] = &[
    188, 234, 168, 141, 91, 54, 127, 126, 66, 108, 74, 127, 86, 181, 21, 173, 213, 69, 176, 73,
    143, 122, 63, 15, 4, 75, 36, 104, 9, 239, 0, 194,
];

// Padding logic verification key / padding logic image id
pub const PADDING_LOGIC_VK: &[u8; 32] = &[
    95, 196, 191, 159, 188, 223, 251, 22, 99, 181, 41, 84, 33, 169, 183, 41, 206, 30, 164, 75, 81,
    95, 141, 226, 84, 246, 88, 154, 232, 67, 169, 239,
];
