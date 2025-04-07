use k256::ecdsa::{
    signature::{Signer, Verifier},
    Error, Signature, SigningKey, VerifyingKey,
};
use k256::{elliptic_curve::rand_core::OsRng, EncodedPoint};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuthorizationSigningKey(SigningKey);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationVerifyingKey(EncodedPoint);

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationSignature(Signature);

impl AuthorizationSigningKey {
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        AuthorizationSigningKey(signing_key)
    }

    pub fn sign(&self, message: &[u8]) -> AuthorizationSignature {
        AuthorizationSignature(self.0.sign(message))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        AuthorizationSigningKey(SigningKey::from_bytes(bytes.into()).unwrap())
    }
}

impl Default for AuthorizationSigningKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for AuthorizationSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for AuthorizationSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(AuthorizationSigningKey::from_bytes(&bytes))
    }
}

impl AuthorizationVerifyingKey {
    pub fn from_signing_key(signing_key: &AuthorizationSigningKey) -> Self {
        let verifying_key = signing_key.0.verifying_key();
        AuthorizationVerifyingKey(verifying_key.to_encoded_point(false))
    }

    pub fn verify(&self, message: &[u8], signature: &AuthorizationSignature) -> Result<(), Error> {
        VerifyingKey::from_encoded_point(&self.0)
            .unwrap()
            .verify(message, signature.inner())
    }
}

impl AuthorizationSignature {
    pub fn inner(&self) -> &Signature {
        &self.0
    }
}

#[test]
fn test_authorization() {
    let signing_key = AuthorizationSigningKey::new();
    let verifying_key = AuthorizationVerifyingKey::from_signing_key(&signing_key);

    let message = b"Hello, world!";
    let signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature).is_ok());
}
