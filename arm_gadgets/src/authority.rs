//! Authority signing and verification using ECDSA over secp256k1.

use anoma_rm_risc0::error::ArmError;
use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    AffinePoint,
};
use serde::{Deserialize, Serialize};

/// The authority's signing key.
#[derive(Clone)]
pub struct AuthoritySigningKey(SigningKey);

/// The authority's verifying key.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityVerifyingKey(AffinePoint);

/// The authority's signature.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySignature(Signature);

impl AuthoritySigningKey {
    /// Generates a new random authority signing key.
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        AuthoritySigningKey(signing_key)
    }

    /// Signs a message with the authority signing key, including a domain separator.
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> AuthoritySignature {
        let mut msg_with_domain =
            Vec::with_capacity(b"ARM_AUTH_V1".len() + domain.len() + message.len());

        // Protocol version prefix
        msg_with_domain.extend_from_slice(b"ARM_AUTH_V1");

        msg_with_domain.extend_from_slice(domain);
        msg_with_domain.extend_from_slice(message);
        AuthoritySignature(self.0.sign(&msg_with_domain))
    }

    /// Serializes the signing key to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// Deserializes the signing key from a byte array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArmError> {
        let signing_key =
            SigningKey::from_bytes(bytes.into()).map_err(|_| ArmError::InvalidSigningKey)?;
        Ok(AuthoritySigningKey(signing_key))
    }
}

impl Default for AuthoritySigningKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for AuthoritySigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for AuthoritySigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        AuthoritySigningKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl AuthorityVerifyingKey {
    /// Creates an AuthorityVerifyingKey from a given AuthoritySigningKey.
    pub fn from_signing_key(signing_key: &AuthoritySigningKey) -> Self {
        let verifying_key = signing_key.0.verifying_key();
        Self::from_affine(*verifying_key.as_affine())
    }

    /// Verifies a signature against the given domain and message.
    pub fn verify(
        &self,
        domain: &[u8],
        message: &[u8],
        signature: &AuthoritySignature,
    ) -> Result<(), ArmError> {
        let mut msg_with_domain =
            Vec::with_capacity(b"ARM_AUTH_V1".len() + domain.len() + message.len());

        // Protocol version prefix
        msg_with_domain.extend_from_slice(b"ARM_AUTH_V1");

        msg_with_domain.extend_from_slice(domain);
        msg_with_domain.extend_from_slice(message);

        VerifyingKey::from_affine(self.0)
            .map_err(|_| ArmError::InvalidPublicKey)?
            .verify(&msg_with_domain, signature.inner())
            .map_err(|_| ArmError::InvalidSignature)
    }

    /// Creates an AuthorityVerifyingKey from an AffinePoint.
    pub fn from_affine(point: AffinePoint) -> Self {
        AuthorityVerifyingKey(point)
    }

    /// Returns a reference to the inner AffinePoint.
    pub fn as_affine(&self) -> &AffinePoint {
        &self.0
    }

    /// Serializes the verifying key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
}

impl AuthoritySignature {
    /// Returns a reference to the inner Signature.
    pub fn inner(&self) -> &Signature {
        &self.0
    }

    /// Serializes the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Deserializes the signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArmError> {
        let sig = Signature::from_bytes(bytes.into()).map_err(|_| ArmError::InvalidSignature)?;
        Ok(AuthoritySignature(sig))
    }
}

impl Default for AuthoritySignature {
    // The default value is only for testing
    fn default() -> Self {
        AuthoritySignature::from_bytes(&[
            101, 32, 148, 79, 63, 230, 254, 97, 75, 207, 23, 50, 92, 222, 89, 100, 165, 2, 71, 210,
            167, 103, 91, 93, 211, 153, 136, 146, 203, 184, 95, 179, 16, 14, 183, 214, 102, 89,
            239, 106, 34, 243, 48, 39, 100, 175, 157, 236, 122, 31, 161, 83, 8, 27, 17, 33, 145,
            161, 164, 137, 140, 209, 239, 25,
        ])
        .unwrap()
    }
}

#[test]
fn test_authorization() {
    let signing_key = AuthoritySigningKey::new();
    let verifying_key = AuthorityVerifyingKey::from_signing_key(&signing_key);

    let domain = b"test_domain";
    let message = b"Hello, world!";
    let signature = signing_key.sign(domain, message);
    // println!("Signature: {:?}", signature.to_bytes());

    assert!(verifying_key.verify(domain, message, &signature).is_ok());
}
