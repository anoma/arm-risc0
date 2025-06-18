// use risc0_zkvm::Digest;

pub const COMPLIANCE_GUEST_ELF: &[u8] = include_bytes!("../elfs/compliance_elf.bin");
pub const PADDING_GUEST_ELF: &[u8] = include_bytes!("../elfs/padding_logic_elf.bin");
pub const TEST_GUEST_ELF: &[u8] = include_bytes!("../elfs/test_logic_elf.bin");

pub const COMPLIANCE_GUEST_ID: &[u8; 32] = &[
    195, 128, 130, 188, 232, 4, 247, 196, 49, 225, 79, 106, 154, 61, 216, 14, 207, 43, 49, 206, 82,
    106, 239, 159, 98, 23, 125, 192, 36, 128, 24, 143,
];

pub const PADDING_GUEST_ID: &[u8; 32] = &[
    45, 67, 213, 252, 205, 10, 108, 113, 58, 97, 164, 10, 245, 99, 159, 149, 149, 15, 210, 94, 137,
    111, 62, 92, 76, 227, 35, 85, 36, 14, 36, 185,
];

pub const TEST_GUEST_ID: &[u8; 32] = &[
    18, 130, 254, 37, 130, 175, 206, 164, 80, 147, 205, 220, 70, 117, 145, 70, 81, 157, 214, 184,
    99, 185, 118, 15, 177, 144, 127, 237, 108, 92, 7, 100,
];
