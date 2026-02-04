//! Standalone Digest type for builds without risc0-zkvm.

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Number of 32-bit words in a Digest.
pub const DIGEST_WORDS: usize = 8;

/// Number of bytes in a Digest.
pub const DIGEST_BYTES: usize = 32;

/// A 32-byte digest represented as 8 little-endian u32 words.
///
/// This is compatible with risc0_zkvm::sha::Digest's internal representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub struct Digest(pub [u32; DIGEST_WORDS]);

impl Digest {
    /// Creates a new Digest from u32 words.
    pub const fn new(words: [u32; DIGEST_WORDS]) -> Self {
        Digest(words)
    }

    /// Create a Digest from 32 bytes.
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        let words: [u32; DIGEST_WORDS] = bytemuck::cast(bytes);
        Digest(words)
    }

    /// Convert to 32 bytes.
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        bytemuck::cast(self.0)
    }

    /// Returns the digest as a slice of u32 words.
    pub fn as_words(&self) -> &[u32; DIGEST_WORDS] {
        &self.0
    }

    /// Returns the digest as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(&self.0)
    }

    /// Create a Digest from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex)?;
        if bytes.len() != DIGEST_BYTES {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; DIGEST_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = core::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; DIGEST_BYTES] = bytes.try_into()?;
        Ok(Self::from_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_roundtrip_bytes() {
        let hex_str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";
        let digest = Digest::from_hex(hex_str).unwrap();
        let bytes = digest.to_bytes();
        let digest2 = Digest::from_bytes(bytes);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_digest_from_hex_nonzero() {
        let hex_str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";
        let digest = Digest::from_hex(hex_str).unwrap();
        assert_ne!(digest, Digest::default());
    }

    #[test]
    fn test_digest_default_is_zero() {
        let digest = Digest::default();
        assert_eq!(digest.as_words(), &[0u32; DIGEST_WORDS]);
        assert_eq!(digest.as_bytes(), &[0u8; DIGEST_BYTES]);
    }

    #[test]
    fn test_digest_words_bytes_consistency() {
        let words = [
            0x01020304u32,
            0x05060708,
            0x090a0b0c,
            0x0d0e0f10,
            0x11121314,
            0x15161718,
            0x191a1b1c,
            0x1d1e1f20,
        ];
        let digest = Digest::new(words);
        assert_eq!(digest.as_words(), &words);
        let bytes = digest.to_bytes();
        assert_eq!(bytes.len(), DIGEST_BYTES);
        let roundtrip = Digest::from_bytes(bytes);
        assert_eq!(roundtrip, digest);
    }
}
