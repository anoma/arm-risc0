//! Delta proof module containing the delta proof, witness, and instance.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{
    elliptic_curve::{scalar::IsHigh, PublicKey, ScalarPrimitive},
    ProjectivePoint, Scalar, SecretKey,
};
use serde::{Deserialize, Serialize};

use crate::error::ArmError;
use sha3::{Digest, Keccak256};

/// The delta proof consists of an ECDSA signature and a recovery ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaProof {
    /// The binding signature(ECDSA).
    pub signature: Signature,
    /// The recovery ID.
    pub recid: RecoveryId,
}

/// The delta witness contains the signing key used to generate the delta proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaWitness {
    /// The signing key.
    pub signing_key: SigningKey,
}

/// The delta instance contains the verifying key and the message used to verify the delta proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaInstance {
    /// The verifying key.
    pub verifying_key: VerifyingKey,
    /// The message that was signed.
    pub message: Vec<u8>,
}

impl DeltaProof {
    /// Generates a delta proof by signing the given message with the provided witness.
    pub fn prove(message: &[u8], witness: &DeltaWitness) -> Result<DeltaProof, ArmError> {
        // Hash the message using Keccak256
        let mut digest = Keccak256::new();
        digest.update(message);

        // Sign the hashed message using RFC6979
        let (signature, recid) = witness
            .signing_key
            .sign_digest_recoverable(digest)
            .map_err(|_| ArmError::DeltaProofGenerationFailed)?;

        // On-chain signatures are not supported when recid is 2 or 3.
        if recid.to_byte() > 1 {
            return Err(ArmError::InvalidDeltaProof);
        }

        Ok(DeltaProof { signature, recid })
    }

    /// Verifies the delta proof against the instance (which carries the message).
    pub fn verify(proof: &DeltaProof, instance: DeltaInstance) -> Result<(), ArmError> {
        // handle recid
        if proof.recid.to_byte() > 1 {
            return Err(ArmError::InvalidDeltaProof);
        }

        // Explicitly check for malleable signatures(s >
        // 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0),
        // even though it prevents the case in the prove above.
        if proof.signature.s().is_high().into() {
            return Err(ArmError::InvalidDeltaProof);
        }

        // Hash the message using Keccak256
        let mut digest = Keccak256::new();
        digest.update(&instance.message);

        // Verify the signature
        let vk = VerifyingKey::recover_from_digest(digest, &proof.signature, proof.recid)
            .map_err(|_| ArmError::DeltaProofVerificationFailed)?;
        if vk != instance.verifying_key {
            return Err(ArmError::DeltaProofVerificationFailed);
        }
        Ok(())
    }

    /// Serializes the delta proof to bytes.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..64].clone_from_slice(&self.signature.to_bytes());
        bytes[64] = self.recid.to_byte() + 27;
        bytes
    }

    /// Deserializes the delta proof from bytes.
    ///
    /// Accepts the v-byte in either the raw `{0, 1}` form or the Ethereum
    /// `{27, 28}` form. `to_bytes` always emits the `{27, 28}` form.
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaProof, ArmError> {
        if bytes.len() != 65 {
            return Err(ArmError::InvalidSignature);
        }
        let raw_v = match bytes[64] {
            v @ (0 | 1) => v,
            v @ (27 | 28) => v - 27,
            _ => return Err(ArmError::InvalidSignature),
        };
        let recid = RecoveryId::from_byte(raw_v).ok_or(ArmError::InvalidSignature)?;
        Ok(DeltaProof {
            signature: Signature::from_bytes((&bytes[0..64]).into())
                .map_err(|_| ArmError::InvalidSignature)?,
            recid,
        })
    }
}

impl DeltaWitness {
    /// Creates a delta witness from a list of secret keys by summing them up.
    pub fn from_scalars(secret_keys: &[Scalar]) -> Result<DeltaWitness, ArmError> {
        if secret_keys.is_empty() {
            return Err(ArmError::EmptyDeltaWitnesses);
        }
        let sum = secret_keys.iter().fold(Scalar::ZERO, |acc, x| acc + x);
        signing_key_from_scalar(sum).map(|signing_key| DeltaWitness { signing_key })
    }

    /// Creates a delta witness from a list of byte vectors representing secret keys.
    pub fn from_bytes_vec(keys: &[Vec<u8>]) -> Result<DeltaWitness, ArmError> {
        let witnesses: Vec<DeltaWitness> = keys
            .iter()
            .map(|key| DeltaWitness::from_bytes(key))
            .collect::<Result<_, _>>()?;
        DeltaWitness::compress(&witnesses)
    }

    /// Creates a delta witness from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaWitness, ArmError> {
        let sk = SecretKey::from_slice(bytes).map_err(|_| ArmError::InvalidSigningKey)?;
        Ok(DeltaWitness {
            signing_key: SigningKey::from(&sk),
        })
    }

    /// Serializes the delta witness to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Composes two delta witnesses by summing their signing keys.
    pub fn compose(&self, other: &DeltaWitness) -> Result<Self, ArmError> {
        let sum = self.signing_key.as_nonzero_scalar().as_ref()
            + other.signing_key.as_nonzero_scalar().as_ref();
        signing_key_from_scalar(sum).map(|signing_key| Self { signing_key })
    }

    /// Compresses a list of delta witnesses into a single delta witness by summing them up.
    pub fn compress(witnesses: &[DeltaWitness]) -> Result<DeltaWitness, ArmError> {
        let (first, rest) = witnesses
            .split_first()
            .ok_or(ArmError::EmptyDeltaWitnesses)?;
        rest.iter().try_fold(first.clone(), |acc, w| acc.compose(w))
    }
}

fn signing_key_from_scalar(scalar: Scalar) -> Result<SigningKey, ArmError> {
    let primitive: ScalarPrimitive<_> = scalar.into();
    let sk =
        SecretKey::from_slice(&primitive.to_bytes()).map_err(|_| ArmError::InvalidSigningKey)?;
    Ok(SigningKey::from(&sk))
}

impl DeltaInstance {
    /// Creates a delta instance from a list of projective points and the signed message.
    pub fn new(deltas: &[ProjectivePoint], message: Vec<u8>) -> Result<DeltaInstance, ArmError> {
        let sum = deltas
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let pk = PublicKey::from_affine(sum.to_affine()).map_err(|_| ArmError::InvalidPublicKey)?;
        let vk = VerifyingKey::from(&pk);
        Ok(DeltaInstance {
            verifying_key: vk,
            message,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_delta_proof() {
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"Hello, world!".to_vec();
        let witness = DeltaWitness { signing_key };
        let proof = DeltaProof::prove(&message, &witness).unwrap();
        let instance = DeltaInstance {
            verifying_key,
            message,
        };

        DeltaProof::verify(&proof, instance).unwrap();
    }

    /// DeltaProof: serialize then deserialize via bincode must round-trip.
    #[test]
    fn delta_proof_bincode_roundtrip() {
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let witness = DeltaWitness { signing_key };
        let proof = DeltaProof::prove(b"roundtrip", &witness).unwrap();

        let encoded = bincode::serialize(&proof).unwrap();
        let decoded: DeltaProof = bincode::deserialize(&encoded).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn delta_proof_from_bytes_rejects_invalid_inputs() {
        assert_eq!(
            DeltaProof::from_bytes(&[0u8; 64]),
            Err(ArmError::InvalidSignature)
        );

        for bad_v in [2u8, 26, 29, 255] {
            let mut bytes = [0u8; 65];
            bytes[64] = bad_v;
            assert_eq!(
                DeltaProof::from_bytes(&bytes),
                Err(ArmError::InvalidSignature),
                "v={bad_v} must be rejected"
            );
        }
    }

    #[test]
    fn delta_proof_from_bytes_accepts_raw_and_ethereum_v() {
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let witness = DeltaWitness { signing_key };
        let proof = DeltaProof::prove(b"v-byte", &witness).unwrap();
        let canonical = proof.to_bytes();

        // Canonical Ethereum-style {27, 28} round-trips.
        assert_eq!(DeltaProof::from_bytes(&canonical).unwrap(), proof);

        // Raw {0, 1} v-byte is also accepted and yields the same proof.
        let mut raw = canonical;
        raw[64] = canonical[64] - 27;
        assert_eq!(DeltaProof::from_bytes(&raw).unwrap(), proof);
    }

    #[test]
    fn empty_delta_witness_inputs_are_rejected() {
        assert_eq!(
            DeltaWitness::from_scalars(&[]),
            Err(ArmError::EmptyDeltaWitnesses)
        );
        assert_eq!(
            DeltaWitness::from_bytes_vec(&[]),
            Err(ArmError::EmptyDeltaWitnesses)
        );
        assert_eq!(
            DeltaWitness::compress(&[]),
            Err(ArmError::EmptyDeltaWitnesses)
        );
    }

    /// DeltaWitness: serialize then deserialize via bincode must round-trip.
    #[test]
    fn delta_witness_bincode_roundtrip() {
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let witness = DeltaWitness { signing_key };

        let encoded = bincode::serialize(&witness).unwrap();
        let decoded: DeltaWitness = bincode::deserialize(&encoded).unwrap();
        assert_eq!(witness, decoded);
    }
}
