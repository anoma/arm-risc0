//! Standalone Digest type for builds without risc0-zkvm.

use serde::{Deserialize, Serialize};

#[cfg(feature = "solana")]
use borsh::{BorshDeserialize, BorshSerialize};

/// Number of 32-bit words in a Digest.
pub const DIGEST_WORDS: usize = 8;

/// Number of bytes in a Digest.
pub const DIGEST_BYTES: usize = 32;

/// A 32-byte digest represented as 8 little-endian u32 words.
///
/// This is compatible with risc0_zkvm::sha::Digest's internal representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub struct Digest(pub [u32; DIGEST_WORDS]);

impl Digest {
    /// Create a Digest from 32 bytes.
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        let words: [u32; DIGEST_WORDS] = bytemuck::cast(bytes);
        Digest(words)
    }

    /// Convert to 32 bytes.
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        bytemuck::cast(self.0)
    }

    /// Get a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(&self.0)
    }

    /// Get a reference to the underlying words.
    pub fn as_words(&self) -> &[u32; DIGEST_WORDS] {
        &self.0
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
