//! Opaque delta proof and witness types (no k256 dependency).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque 65-byte delta proof (signature bytes + recovery ID).
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaProof(pub [u8; 65]);

/// Opaque 32-byte delta witness (signing key bytes).
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaWitness(pub [u8; 32]);

impl Serialize for DeltaProof {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for DeltaProof {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        bytes.try_into().map(DeltaProof).map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 65 bytes, got {}", v.len()))
        })
    }
}

impl Serialize for DeltaWitness {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for DeltaWitness {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        bytes.try_into().map(DeltaWitness).map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}
