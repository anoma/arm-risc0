
use serde::{Deserialize, Serialize};
use serde_bytes;

#[derive(Serialize, Deserialize)]
pub struct GenericEnv {
    pub data: serde_bytes::ByteBuf,
}

