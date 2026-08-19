//! Delta proof and witness as structured protocol data.
//!
//! These types are field-element bytes plus pure validity checks — no
//! cryptographic engine is reachable from construction or deserialization,
//! so decoding a wire transaction can never execute curve arithmetic
//! (which, among other things, cannot run within Solana's SBF stack
//! limits). Signing, verification, and witness composition are engine
//! operations: k256 on the host (`anoma-rm-risc0::delta_proof`), syscalls
//! on Solana (`anoma-rm-solana`).
//!
//! The wire encodings are unchanged from the k256-typed predecessors and
//! are pinned by the committed vectors in `anoma-rm-risc0`'s
//! `wire_vectors` test: 65 bytes for the proof (r ‖ s ‖ v with the v-byte
//! Ethereum-style, +27) and 32 bytes for the witness scalar.

use crate::error::ArmError;
use serde::{Deserialize, Serialize};

/// The secp256k1 group order `n`, big-endian.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Half the secp256k1 group order, big-endian — the low-s malleability
/// boundary: a canonical signature has `s <= SECP256K1_HALF_ORDER`.
pub const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `true` iff the big-endian 32-byte value is a valid scalar in `[1, n-1]`.
fn is_valid_scalar(bytes: &[u8; 32]) -> bool {
    *bytes != [0u8; 32] && *bytes < SECP256K1_ORDER
}

/// The delta proof: a recoverable ECDSA signature over the keccak hash of
/// the delta message — 64 signature bytes (`r ‖ s`, big-endian) and a
/// recovery id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaProof {
    /// The signature bytes, `r ‖ s` big-endian. Both components are
    /// validated to lie in `[1, n-1]` at construction.
    pub signature: [u8; 64],
    /// The recovery id, 0 or 1 (stored raw; the wire form adds 27).
    pub recovery_id: u8,
}

impl DeltaProof {
    /// Serializes the delta proof to bytes (v-byte Ethereum-style, +27).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..64].copy_from_slice(&self.signature);
        bytes[64] = self.recovery_id + 27;
        bytes
    }

    /// Deserializes the delta proof from bytes, validating that `r` and `s`
    /// are scalars in `[1, n-1]` and the recovery id is 0 or 1.
    ///
    /// Accepts the v-byte in either the raw `{0, 1}` form or the Ethereum
    /// `{27, 28}` form. `to_bytes` always emits the `{27, 28}` form.
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaProof, ArmError> {
        if bytes.len() != 65 {
            return Err(ArmError::InvalidSignature);
        }
        let recovery_id = match bytes[64] {
            v @ (0 | 1) => v,
            v @ (27 | 28) => v - 27,
            _ => return Err(ArmError::InvalidSignature),
        };
        let r: [u8; 32] = bytes[0..32].try_into().expect("length checked");
        let s: [u8; 32] = bytes[32..64].try_into().expect("length checked");
        if !is_valid_scalar(&r) || !is_valid_scalar(&s) {
            return Err(ArmError::InvalidSignature);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[0..64]);
        Ok(DeltaProof {
            signature,
            recovery_id,
        })
    }

    /// Rejects malleable signatures: a canonical signature has
    /// `s <= SECP256K1_HALF_ORDER`. Every verifier engine enforces this
    /// before recovery.
    pub fn check_low_s(&self) -> Result<(), ArmError> {
        let s: [u8; 32] = self.signature[32..64].try_into().expect("fixed length");
        if s > SECP256K1_HALF_ORDER {
            return Err(ArmError::InvalidDeltaProof);
        }
        Ok(())
    }
}

/// The delta witness: the signing-key scalar for the delta proof,
/// validated to lie in `[1, n-1]` at construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaWitness {
    scalar: [u8; 32],
}

impl DeltaWitness {
    /// Creates a delta witness from big-endian scalar bytes, validating the
    /// range `[1, n-1]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaWitness, ArmError> {
        let scalar: [u8; 32] = bytes.try_into().map_err(|_| ArmError::InvalidSigningKey)?;
        if !is_valid_scalar(&scalar) {
            return Err(ArmError::InvalidSigningKey);
        }
        Ok(DeltaWitness { scalar })
    }

    /// Serializes the delta witness to big-endian scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar
    }

    /// The big-endian scalar bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.scalar
    }
}

impl Serialize for DeltaProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for DeltaProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 65 {
            return Err(serde::de::Error::custom(
                "Invalid byte length for DeltaProof",
            ));
        }
        DeltaProof::from_bytes(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize DeltaProof: {:?}", e))
        })
    }
}

impl Serialize for DeltaWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for DeltaWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(
                "Invalid byte length for DeltaWitness",
            ));
        }
        DeltaWitness::from_bytes(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize DeltaWitness: {:?}", e))
        })
    }
}

#[cfg(feature = "borsh")]
mod borsh_impls {
    use super::{DeltaProof, DeltaWitness};
    use borsh::io::{Error, ErrorKind, Read, Result, Write};
    use borsh::{BorshDeserialize, BorshSerialize};

    // Fixed-width encodings, validated on read exactly like the serde path:
    // 65 bytes for the proof (v-byte Ethereum-style, +27), 32 for the witness.

    impl BorshSerialize for DeltaProof {
        fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
            writer.write_all(&self.to_bytes())
        }
    }

    impl BorshDeserialize for DeltaProof {
        fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
            let mut bytes = [0u8; 65];
            reader.read_exact(&mut bytes)?;
            DeltaProof::from_bytes(&bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid delta proof bytes"))
        }
    }

    impl BorshSerialize for DeltaWitness {
        fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
            writer.write_all(&self.to_bytes())
        }
    }

    impl BorshDeserialize for DeltaWitness {
        fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            DeltaWitness::from_bytes(&bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid delta witness bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_proof_from_bytes_rejects_invalid_inputs() {
        assert_eq!(
            DeltaProof::from_bytes(&[0u8; 64]),
            Err(ArmError::InvalidSignature)
        );

        for bad_v in [2u8, 26, 29, 255] {
            let mut bytes = [1u8; 65];
            bytes[64] = bad_v;
            assert_eq!(
                DeltaProof::from_bytes(&bytes),
                Err(ArmError::InvalidSignature),
                "v={bad_v} must be rejected"
            );
        }

        // zero r / zero s / r or s == n are not valid scalars
        let mut zero_r = [1u8; 65];
        zero_r[0..32].copy_from_slice(&[0u8; 32]);
        zero_r[64] = 27;
        assert_eq!(
            DeltaProof::from_bytes(&zero_r),
            Err(ArmError::InvalidSignature)
        );
        let mut s_is_n = [1u8; 65];
        s_is_n[32..64].copy_from_slice(&SECP256K1_ORDER);
        s_is_n[64] = 27;
        assert_eq!(
            DeltaProof::from_bytes(&s_is_n),
            Err(ArmError::InvalidSignature)
        );
    }

    #[test]
    fn delta_proof_from_bytes_accepts_raw_and_ethereum_v() {
        let mut canonical = [1u8; 65];
        canonical[64] = 28;
        let proof = DeltaProof::from_bytes(&canonical).unwrap();
        assert_eq!(proof.recovery_id, 1);
        assert_eq!(proof.to_bytes(), canonical);

        let mut raw = canonical;
        raw[64] = 1;
        assert_eq!(DeltaProof::from_bytes(&raw).unwrap(), proof);
    }

    #[test]
    fn low_s_boundary() {
        let mut sig = [1u8; 65];
        sig[32..64].copy_from_slice(&SECP256K1_HALF_ORDER);
        sig[64] = 27;
        DeltaProof::from_bytes(&sig).unwrap().check_low_s().unwrap();

        let mut high = SECP256K1_HALF_ORDER;
        high[31] += 1;
        sig[32..64].copy_from_slice(&high);
        assert_eq!(
            DeltaProof::from_bytes(&sig).unwrap().check_low_s(),
            Err(ArmError::InvalidDeltaProof)
        );
    }

    #[test]
    fn delta_witness_range_validation() {
        assert!(DeltaWitness::from_bytes(&[0x11; 32]).is_ok());
        assert_eq!(
            DeltaWitness::from_bytes(&[0u8; 32]),
            Err(ArmError::InvalidSigningKey)
        );
        assert_eq!(
            DeltaWitness::from_bytes(&SECP256K1_ORDER),
            Err(ArmError::InvalidSigningKey)
        );
        assert_eq!(
            DeltaWitness::from_bytes(&[0xff; 32]),
            Err(ArmError::InvalidSigningKey)
        );
        assert_eq!(
            DeltaWitness::from_bytes(&[1, 2, 3]).err(),
            Some(ArmError::InvalidSigningKey)
        );
    }

    /// One below the order is the largest valid scalar.
    #[test]
    fn delta_witness_accepts_n_minus_one() {
        let mut n_minus_one = SECP256K1_ORDER;
        n_minus_one[31] -= 1;
        assert!(DeltaWitness::from_bytes(&n_minus_one).is_ok());
    }
}
