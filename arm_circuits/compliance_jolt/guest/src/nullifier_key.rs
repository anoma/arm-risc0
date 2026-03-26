use crate::digest::{hash_bytes, Digest, DIGEST_BYTES};

#[derive(Clone, PartialEq, Eq)]
pub struct NullifierKey([u8; DIGEST_BYTES]);

impl NullifierKey {
    pub fn commit(&self) -> NullifierKeyCommitment { NullifierKeyCommitment(hash_bytes(&self.0)) }
    pub fn inner(&self) -> &[u8] { &self.0 }
}
impl Default for NullifierKey { fn default() -> Self { NullifierKey([0u8; DIGEST_BYTES]) } }

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NullifierKeyCommitment(Digest);

impl NullifierKeyCommitment {
    pub fn inner(&self) -> Digest { self.0 }
    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
}
impl Default for NullifierKeyCommitment { fn default() -> Self { NullifierKey::default().commit() } }
