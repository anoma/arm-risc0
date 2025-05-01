use risc0_zkvm::sha::DIGEST_BYTES;

pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

pub const PRF_EXPAND_PERSONALIZATION_LEN: usize = 16;
pub const PRF_EXPAND_PERSONALIZATION: &[u8; PRF_EXPAND_PERSONALIZATION_LEN] = b"RISC0_ExpandSeed";
pub const PRF_EXPAND_PSI: u8 = 0;
pub const PRF_EXPAND_RCM: u8 = 1;

pub const TRIVIAL_RESOURCE_LOGIC_VK: &[u8] = b"trivial_resource_logic_vk";

pub const TREE_DEPTH: usize = 32;

pub const DEFAULT_BYTES: usize = 32;
pub const QUANTITY_BYTES: usize = 16;

pub const RESOURCE_BYTES: usize = DIGEST_BYTES
    + DEFAULT_BYTES
    + DEFAULT_BYTES
    + QUANTITY_BYTES
    + 1
    + DIGEST_BYTES
    + DIGEST_BYTES
    + DEFAULT_BYTES;

pub const TRIVIAL_RESOURCE_LOGIC: [u32; 8] = [
    1730895203, 687735437, 1589405236, 1676522030, 609845429, 3611972331, 391524015, 1550105629,
];
