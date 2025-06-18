// use risc0_zkvm::Digest;

pub const COMPLIANCE_GUEST_ELF: &[u8] = include_bytes!("../elfs/compliance_elf.bin");
pub const PADDING_GUEST_ELF: &[u8] = include_bytes!("../elfs/padding_logic_elf.bin");
pub const TEST_GUEST_ELF: &[u8] = include_bytes!("../elfs/test_logic_elf.bin");

pub const COMPLIANCE_GUEST_ID: &[u8; 32] = &[
    188, 234, 168, 141, 91, 54, 127, 126, 66, 108, 74, 127, 86, 181, 21, 173, 213, 69, 176, 73,
    143, 122, 63, 15, 4, 75, 36, 104, 9, 239, 0, 194,
];

pub const PADDING_GUEST_ID: &[u8; 32] = &[
    95, 196, 191, 159, 188, 223, 251, 22, 99, 181, 41, 84, 33, 169, 183, 41, 206, 30, 164, 75, 81,
    95, 141, 226, 84, 246, 88, 154, 232, 67, 169, 239,
];

pub const TEST_GUEST_ID: &[u8; 32] = &[
    115, 46, 90, 182, 221, 164, 139, 3, 72, 121, 239, 156, 172, 144, 63, 152, 226, 182, 236, 83,
    133, 151, 61, 113, 135, 101, 21, 20, 64, 143, 50, 150,
];
