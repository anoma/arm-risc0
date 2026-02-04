//! Standalone Digest type, wire-compatible with `risc0_zkvm::sha::Digest`.

use serde::{Deserialize, Serialize};

/// Number of bytes in a digest.
pub const DIGEST_BYTES: usize = 32;
/// Number of u32 words in a digest.
pub const DIGEST_WORDS: usize = 8;

/// A SHA-256 digest represented as 8 little-endian u32 words.
///
/// This type is wire-compatible with `risc0_zkvm::sha::Digest`:
/// both store `[u32; 8]` and expose bytes via `bytemuck::cast_slice`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest([u32; DIGEST_WORDS]);

impl Digest {
    /// Creates a new Digest from u32 words.
    pub const fn new(words: [u32; DIGEST_WORDS]) -> Self {
        Digest(words)
    }

    /// Returns the digest as a slice of u32 words.
    pub fn as_words(&self) -> &[u32; DIGEST_WORDS] {
        &self.0
    }

    /// Returns the digest as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(&self.0)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != DIGEST_BYTES {
            return Err("Invalid byte length for Digest");
        }
        Ok(Digest(*bytemuck::from_bytes(bytes)))
    }
}

impl hex::FromHex for Digest {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = hex::decode(hex)?;
        if bytes.len() != DIGEST_BYTES {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        Ok(Digest(*bytemuck::from_bytes(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_roundtrip_bytes() {
        let hex_str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";
        let digest = <Digest as hex::FromHex>::from_hex(hex_str).unwrap();
        let bytes = digest.as_bytes();
        let digest2 = Digest::try_from(bytes).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_digest_from_hex_nonzero() {
        let hex_str = "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06";
        let digest = <Digest as hex::FromHex>::from_hex(hex_str).unwrap();
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
        let bytes = digest.as_bytes();
        assert_eq!(bytes.len(), DIGEST_BYTES);
        let roundtrip = Digest::try_from(bytes).unwrap();
        assert_eq!(roundtrip, digest);
    }
}
