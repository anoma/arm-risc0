use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogicInstance {
    pub tag: Digest,
    pub is_consumed: bool,
    pub root: Digest,
    pub cipher: Vec<u8>,
    pub app_data: Vec<ExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpirableBlob {
    pub blob: Vec<u8>,
    pub deletion_criterion: u8,
}
