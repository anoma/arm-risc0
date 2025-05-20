use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::{sha::DIGEST_BYTES, Digest};

pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

pub const PRF_EXPAND_PERSONALIZATION_LEN: usize = 16;
pub const PRF_EXPAND_PERSONALIZATION: &[u8; PRF_EXPAND_PERSONALIZATION_LEN] = b"RISC0_ExpandSeed";
pub const PRF_EXPAND_PSI: u8 = 0;
pub const PRF_EXPAND_RCM: u8 = 1;

pub const TRIVIAL_RESOURCE_LOGIC_VK: &[u8] = b"trivial_resource_logic_vk";

pub const COMMITMENT_TREE_DEPTH: usize = 32;

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

lazy_static! {
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("7e70786b1d52fc0412d75203ef2ac22de13d9596ace8a5a1ed5324c3ed7f31c3")
            .unwrap();
    pub static ref PADDING_LEAVE: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}
