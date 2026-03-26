extern crate alloc;
use alloc::vec::Vec;

pub const DIGEST_BYTES: usize = 32;
pub const DIGEST_WORDS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(align(4))]
pub struct Digest([u8; DIGEST_BYTES]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] { &self.0 }
    pub fn to_words(&self) -> [u32; DIGEST_WORDS] {
        let mut words = [0u32; DIGEST_WORDS];
        for i in 0..DIGEST_WORDS {
            words[i] = u32::from_le_bytes([
                self.0[i * 4], self.0[i * 4 + 1], self.0[i * 4 + 2], self.0[i * 4 + 3],
            ]);
        }
        words
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != DIGEST_BYTES { return None; }
        let mut arr = [0u8; DIGEST_BYTES];
        arr.copy_from_slice(&bytes);
        Some(Digest(arr))
    }
}
impl Default for Digest { fn default() -> Self { Digest([0u8; DIGEST_BYTES]) } }
impl AsRef<[u8]> for Digest { fn as_ref(&self) -> &[u8] { &self.0 } }
impl From<[u8; DIGEST_BYTES]> for Digest { fn from(bytes: [u8; DIGEST_BYTES]) -> Self { Digest(bytes) } }

pub fn hash_bytes(data: &[u8]) -> Digest {
    Digest(jolt_inlines_sha2::Sha256::digest(data))
}

pub fn hash_words(words: &[u32]) -> Digest {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words { bytes.extend_from_slice(&w.to_le_bytes()); }
    hash_bytes(&bytes)
}
