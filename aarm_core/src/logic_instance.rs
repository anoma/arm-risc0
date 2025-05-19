use crate::encryption::Ciphertext;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LogicInstance {
    pub tag: Digest,
    pub is_consumed: bool,
    pub root: Digest,
    pub cipher: Ciphertext,
    pub app_data: Vec<u8>,
}
