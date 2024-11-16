use crate::constants::DEFAULT_BYTES;
use serde::{Deserialize, Serialize}; 
use risc0_zkvm::sha::Digest;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LogicInstance {
    /// Nullifier of input resource or commitment of output resource
    pub self_resource_id: [u8; DEFAULT_BYTES],
    /// The merkle root of resources
    pub root: Digest,
    pub cipher_text_elem0: [u8; DEFAULT_BYTES],
    pub cipher_text_elem1: [u8; DEFAULT_BYTES],
    pub cipher_text_elem2: [u8; DEFAULT_BYTES],
    pub cipher_text_elem3: [u8; DEFAULT_BYTES],
    pub cipher_text_elem4: [u8; DEFAULT_BYTES],
    pub cipher_text_elem5: [u8; DEFAULT_BYTES],
    pub cipher_text_elem6: [u8; DEFAULT_BYTES],
    pub cipher_text_elem7: [u8; DEFAULT_BYTES],
    pub cipher_text_elem8: [u8; DEFAULT_BYTES],
    pub cipher_text_elem9: [u8; DEFAULT_BYTES],
    pub mac: [u8; DEFAULT_BYTES],
    pub pk_x: [u8; DEFAULT_BYTES],
    pub pk_y: [u8; DEFAULT_BYTES],
    pub nonce: Digest,
}