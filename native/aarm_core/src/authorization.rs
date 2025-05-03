use k256::ecdsa::{
    signature::{Signer, Verifier},
    Error, Signature, SigningKey, VerifyingKey,
};
use k256::{
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    AffinePoint,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuthorizationSigningKey(SigningKey);

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationVerifyingKey(AffinePoint);

#[derive(Clone, Copy, Serialize, Deserialize)]
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
        Self::from_affine(*verifying_key.as_affine())
    }

    pub fn verify(&self, message: &[u8], signature: &AuthorizationSignature) -> Result<(), Error> {
        VerifyingKey::from_affine(self.0)
            .unwrap()
            .verify(message, signature.inner())
    }

    pub fn from_affine(point: AffinePoint) -> Self {
        AuthorizationVerifyingKey(point)
    }

    pub fn as_affine(&self) -> &AffinePoint {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
}

impl AuthorizationSignature {
    pub fn inner(&self) -> &Signature {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        AuthorizationSignature(Signature::from_bytes(bytes.into()).unwrap())
    }
}

impl Default for AuthorizationSignature {
    fn default() -> Self {
        AuthorizationSignature::from_bytes(&[
            101, 32, 148, 79, 63, 230, 254, 97, 75, 207, 23, 50, 92, 222, 89, 100, 165, 2, 71, 210,
            167, 103, 91, 93, 211, 153, 136, 146, 203, 184, 95, 179, 16, 14, 183, 214, 102, 89,
            239, 106, 34, 243, 48, 39, 100, 175, 157, 236, 122, 31, 161, 83, 8, 27, 17, 33, 145,
            161, 164, 137, 140, 209, 239, 25,
        ])
    }
}

#[test]
fn test_authorization() {
    let signing_key = AuthorizationSigningKey::new();
    let verifying_key = AuthorizationVerifyingKey::from_signing_key(&signing_key);

    let message = b"Hello, world!";
    let signature = signing_key.sign(message);
    // println!("Signature: {:?}", signature.to_bytes());

    assert!(verifying_key.verify(message, &signature).is_ok());
}
