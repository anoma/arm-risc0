// use risc0_zkvm::Digest;

pub const COMPLIANCE_GUEST_ELF: &[u8] = include_bytes!("../elfs/compliance_elf.bin");
pub const PADDING_GUEST_ELF: &[u8] = include_bytes!("../elfs/padding_logic_elf.bin");
pub const TEST_GUEST_ELF: &[u8] = include_bytes!("../elfs/test_logic_elf.bin");

pub const COMPLIANCE_GUEST_ID: &[u8; 32] = &[
    165, 175, 10, 214, 188, 44, 60, 191, 252, 223, 96, 125, 106, 246, 242, 56, 106, 18, 124, 104,
    84, 139, 240, 53, 19, 255, 115, 56, 2, 183, 130, 117,
];

pub const PADDING_GUEST_ID: &[u8; 32] = &[
    84, 142, 161, 226, 166, 168, 204, 90, 217, 199, 254, 94, 147, 107, 247, 145, 58, 115, 14, 229,
    163, 237, 227, 234, 84, 183, 230, 29, 73, 163, 163, 28,
];

pub const TEST_GUEST_ID: &[u8; 32] = &[
    218, 94, 150, 48, 183, 122, 176, 209, 107, 237, 228, 239, 109, 157, 243, 58, 24, 232, 163, 212,
    13, 223, 138, 109, 208, 204, 191, 43, 76, 237, 183, 249,
];
