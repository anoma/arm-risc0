use crate::encryption::Ciphertext;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogicInstance {
    pub tag: Digest,
    pub is_consumed: bool,
    pub root: Digest,
    pub cipher: Ciphertext,
    pub app_data: Vec<ExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpirableBlob {
    pub blob: Vec<u8>,
    pub deletion_criterion: u8,
}
