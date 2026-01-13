//! Delta proof module containing the delta proof, witness, and instance.

use crate::error::ArmError;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{
    elliptic_curve::{scalar::IsHigh, PublicKey, ScalarPrimitive},
    ProjectivePoint, Scalar, SecretKey,
};
use serde::{Deserialize, Serialize};
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

/// The delta instance contains the verifying key used to verify the delta proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaInstance {
    /// The verifying key.
    pub verifying_key: VerifyingKey,
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

    /// Verifies the delta proof against the given message and instance.
    pub fn verify(
        message: &[u8],
        proof: &DeltaProof,
        instance: DeltaInstance,
    ) -> Result<(), ArmError> {
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
        digest.update(message);

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
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaProof, ArmError> {
        Ok(DeltaProof {
            signature: Signature::from_bytes((&bytes[0..64]).into())
                .map_err(|_| ArmError::InvalidSignature)?,
            recid: RecoveryId::from_byte(bytes[64] - 27).ok_or(ArmError::InvalidSignature)?,
        })
    }
}

impl DeltaWitness {
    /// Creates a delta witness from a list of secret keys by summing them up.
    pub fn from_scalars(secret_keys: &[Scalar]) -> DeltaWitness {
        let sum: ScalarPrimitive<_> = secret_keys
            .iter()
            .fold(Scalar::ZERO, |acc, x| acc + x)
            .into();
        let sk: SecretKey = SecretKey::new(sum);
        let signing_key = SigningKey::from(&sk);
        DeltaWitness { signing_key }
    }

    /// Creates a delta witness from a list of byte vectors representing secret keys.
    pub fn from_bytes_vec(keys: &[Vec<u8>]) -> Result<DeltaWitness, ArmError> {
        let witnesses: Result<Vec<DeltaWitness>, ArmError> = keys
            .iter()
            .map(|key| DeltaWitness::from_bytes(key))
            .collect();
        Ok(DeltaWitness::compress(&witnesses?))
    }

    /// Creates a delta witness from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DeltaWitness, ArmError> {
        Ok(DeltaWitness {
            signing_key: SigningKey::from_bytes(bytes.into())
                .map_err(|_| ArmError::InvalidSigningKey)?,
        })
    }

    /// Serializes the delta witness to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Composes two delta witnesses by summing their signing keys.
    pub fn compose(&self, other: &DeltaWitness) -> Self {
        let sum = self.signing_key.as_nonzero_scalar().as_ref()
            + other.signing_key.as_nonzero_scalar().as_ref();
        let sk: SecretKey = SecretKey::new(sum.into());
        Self {
            signing_key: SigningKey::from(sk),
        }
    }

    /// Compresses a list of delta witnesses into a single delta witness by summing them up.
    pub fn compress(witnesses: &[DeltaWitness]) -> DeltaWitness {
        let mut sum = witnesses[0].clone();
        for witness in witnesses.iter().skip(1) {
            sum = sum.compose(witness);
        }
        sum
    }
}

impl DeltaInstance {
    /// Creates a delta instance from a list of projective points by summing them up.
    pub fn from_deltas(deltas: &[ProjectivePoint]) -> Result<DeltaInstance, ArmError> {
        let sum = deltas
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let pk = PublicKey::from_affine(sum.to_affine()).map_err(|_| ArmError::InvalidPublicKey)?;
        let vk = VerifyingKey::from(&pk);
        Ok(DeltaInstance { verifying_key: vk })
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
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        DeltaWitness::from_bytes(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize DeltaWitness: {:?}", e))
        })
    }
}
