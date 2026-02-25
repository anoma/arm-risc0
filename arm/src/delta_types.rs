//! Feature-conditional delta witness and proof types.

#[cfg(feature = "k256")]
pub use crate::delta_proof::{DeltaProof, DeltaWitness};

#[cfg(not(feature = "k256"))]
pub use self::placeholder::{DeltaProof, DeltaWitness};

/// Opaque placeholder types when k256 is unavailable.
#[cfg(not(feature = "k256"))]
mod placeholder {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Opaque 65-byte delta proof (signature + recovery ID).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DeltaProof(pub [u8; 65]);

    /// Opaque 32-byte delta witness (signing key).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DeltaWitness(pub [u8; 32]);

    impl DeltaWitness {
        /// Panics - composition requires k256.
        pub fn compose(&self, _other: &DeltaWitness) -> DeltaWitness {
            panic!("DeltaWitness::compose requires k256 feature")
        }
    }

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
            <[u8; 32]>::deserialize(d).map(DeltaWitness)
        }
    }
}
