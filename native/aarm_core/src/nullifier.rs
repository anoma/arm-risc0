use risc0_zkvm::sha::{Sha256, Digest, Impl, DIGEST_BYTES};
use serde::{Deserialize, Serialize};

/// Nullifier secret key
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Nsk(Digest);

impl Nsk {
    pub fn new(nsk: Digest) -> Nsk {
        Nsk(nsk)
    }
    /// Compute the corresponding nullifier public key
    pub fn public_key(&self) -> Npk {
        let bytes: [u8; DIGEST_BYTES] = *self.0.as_ref();
        Npk(*Impl::hash_bytes(&bytes))
    }
    pub fn inner(&self) -> Digest {
        self.0
    }
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Nsk {
        Nsk(Digest::from_bytes(bytes))
    }
}

/// Nullifier public key
#[derive(Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Npk(Digest);

impl Npk {
    pub fn inner(&self) -> Digest {
        self.0
    }

    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Npk {
        Npk(Digest::from_bytes(bytes))
    }
}
