//! Opaque delta proof and witness types (no k256 dependency).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque 65-byte delta proof (signature bytes + recovery ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaProof(pub [u8; 65]);

/// Opaque 32-byte delta witness (signing key bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaWitness(pub [u8; 32]);

impl Serialize for DeltaProof {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Use serialize_seq so that RISC0 serde (which packs 4 bytes per u32
        // word in serialize_bytes but stores 1 byte per word in serialize_seq)
        // stays consistent with Vec<u8>::deserialize on the guest side.
        // Bincode treats serialize_bytes and serialize_seq(u8) identically.
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for byte in &self.0 {
            serde::ser::SerializeSeq::serialize_element(&mut seq, byte)?;
        }
        serde::ser::SerializeSeq::end(seq)
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
        // Same rationale as DeltaProof: use serialize_seq for RISC0 serde
        // compatibility while remaining wire-compatible with bincode.
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for byte in &self.0 {
            serde::ser::SerializeSeq::serialize_element(&mut seq, byte)?;
        }
        serde::ser::SerializeSeq::end(seq)
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
