use crate::encryption::Ciphertext;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogicInstance {
    pub tag: Vec<u8>,
    pub is_consumed: bool,
    pub root: Vec<u8>,
    pub app_data: Vec<ExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpirableBlob {
    pub blob: Vec<u8>,
    pub deletion_criterion: u8,
}

impl ExpirableBlob {
    pub fn new(blob: Vec<u8>, deletion_criterion: u8) -> Self {
        ExpirableBlob {
            blob,
            deletion_criterion,
        }
    }
}

impl From<Ciphertext> for ExpirableBlob {
    fn from(ciphertext: Ciphertext) -> Self {
        ExpirableBlob {
            blob: ciphertext.inner(),
            deletion_criterion: 0, // Default deletion criterion
        }
    }
}
