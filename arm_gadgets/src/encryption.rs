use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use arm::{
    error::ArmError,
    utils::{bytes_to_words, hash_bytes, words_to_bytes},
};
use k256::{
    elliptic_curve::{
        group::{prime::PrimeCurveAffine, Group, GroupEncoding},
        Field,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Scalar);

impl SecretKey {
    pub fn new(sk: Scalar) -> Self {
        SecretKey(sk)
    }

    pub fn random() -> Self {
        let sk = Scalar::random(&mut OsRng);
        SecretKey(sk)
    }

    pub fn inner(&self) -> &Scalar {
        &self.0
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey(Scalar::ONE)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn from_bytes(cipher: Vec<u8>) -> Self {
        Ciphertext(cipher)
    }

    pub fn from_words(words: &[u32]) -> Self {
        Ciphertext(words_to_bytes(words).to_vec())
    }

    pub fn inner(&self) -> &[u8] {
        &self.0
    }

    pub fn as_words(&self) -> Vec<u32> {
        bytes_to_words(self.inner())
    }

    pub fn encrypt(
        message: &Vec<u8>,
        receiver_pk: &AffinePoint,
        sender_sk: &SecretKey,
    ) -> Result<Self, ArmError> {
        let nonce: [u8; 12] = OsRng.gen();
        Self::encrypt_with_nonce(message, receiver_pk, sender_sk, nonce)
    }

    // used in circuits where nonce is provided
    pub fn encrypt_with_nonce(
        message: &Vec<u8>,
        receiver_pk: &AffinePoint,
        sender_sk: &SecretKey,
        nonce: [u8; 12],
    ) -> Result<Self, ArmError> {
        // Generate the secret key using Diffie-Hellman exchange
        let inner_secret_key = InnerSecretKey::from_encryption(receiver_pk, sender_sk.inner())?;

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&inner_secret_key.inner());

        // Encrypt with AES-256-GCM
        let cipher = aes_gcm
            .encrypt(&nonce.into(), message.as_ref())
            .map_err(|_| ArmError::EncryptionFailed)?;

        let pk = generate_public_key(sender_sk.inner());
        let cipher = InnerCiphert { cipher, nonce, pk };
        Ok(Self(
            bincode::serialize(&cipher).map_err(|_| ArmError::SerializationError)?,
        ))
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<SecurePlaintext, ArmError> {
        if self.inner().is_empty() {
            return Err(ArmError::DecryptionFailed);
        }
        let cipher: InnerCiphert =
            bincode::deserialize(self.inner()).map_err(|_| ArmError::DeserializationError)?;
        // Generate the secret key using Diffie-Hellman exchange
        let inner_secret_key = InnerSecretKey::from_decryption(&cipher.pk, sk.inner())?;

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&inner_secret_key.inner());

        // Decrypt with AES-256-GCM
        let plaintext = aes_gcm
            .decrypt(&cipher.nonce.into(), cipher.cipher.as_ref())
            .map_err(|_| ArmError::DecryptionFailed)?;

        Ok(SecurePlaintext::new(plaintext))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InnerCiphert {
    // AES GCM encrypted message
    pub cipher: Vec<u8>,
    // 96-bits; unique per message
    pub nonce: [u8; 12],
    // Sender's public key
    pub pk: AffinePoint,
}

#[derive(Debug, Clone)]
struct InnerSecretKey(Key<Aes256Gcm>);

// implement Zeroize manually
impl Zeroize for InnerSecretKey {
    fn zeroize(&mut self) {
        // Zero the Key's bytes
        // Key<Aes256Gcm> is GenericArray<u8, U32>
        self.0.as_mut_slice().zeroize();
    }
}

// Mark as ZeroizeOnDrop - auto-generates Drop impl that calls zeroize()
impl ZeroizeOnDrop for InnerSecretKey {}

impl InnerSecretKey {
    pub fn from_encryption(pk: &AffinePoint, sk: &Scalar) -> Result<Self, ArmError> {
        // Reject identity point
        if bool::from(pk.is_identity()) {
            return Err(ArmError::InvalidPublicKey);
        }

        let pk = ProjectivePoint::from(*pk);
        let shared_point = pk * sk;
        Self::generate_shared_key(&shared_point, &pk)
    }

    pub fn from_decryption(pk: &AffinePoint, sk: &Scalar) -> Result<Self, ArmError> {
        // Reject identity point
        if bool::from(pk.is_identity()) {
            return Err(ArmError::InvalidPublicKey);
        }

        let shared_point = ProjectivePoint::from(*pk) * sk;
        let pk = ProjectivePoint::GENERATOR * sk;
        Self::generate_shared_key(&shared_point, &pk)
    }

    fn generate_shared_key(
        shared_point: &ProjectivePoint,
        pk: &ProjectivePoint,
    ) -> Result<Self, ArmError> {
        // Reject identity point
        if bool::from(shared_point.is_identity()) {
            return Err(ArmError::InvalidSharedSecret);
        }

        // Reject identity point
        if bool::from(pk.is_identity()) {
            return Err(ArmError::InvalidPublicKey);
        }

        let pk_bytes = pk.to_bytes();
        let key_bytes = shared_point.to_bytes();
        let mut concat = [&pk_bytes[..], &key_bytes[..]].concat();
        let hash = hash_bytes(&concat);

        // Zero intermediate concatenated bytes containing shared secret
        concat.zeroize();

        let shared_key = hash.as_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&shared_key[..32]);
        Ok(InnerSecretKey(*key))
    }

    pub fn inner(&self) -> Key<Aes256Gcm> {
        self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePlaintext(Vec<u8>);

impl SecurePlaintext {
    pub fn new(data: Vec<u8>) -> Self {
        SecurePlaintext(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn generate_public_key(sk: &Scalar) -> AffinePoint {
    // Compute public key as generator * private key
    (ProjectivePoint::GENERATOR * sk).to_affine()
}

/// Generates a random private key (Scalar) and its corresponding public key (ProjectivePoint)
pub fn random_keypair() -> (SecretKey, AffinePoint) {
    let sk = Scalar::random(&mut OsRng);
    let pk = generate_public_key(&sk);

    (SecretKey::new(sk), pk)
}

#[test]
fn test_encryption() {
    // Generate a random sender's private key
    let sender_sk = SecretKey::random();
    // Generate a keypair for the receiver
    let (receiver_sk, receiver_pk) = random_keypair();

    // Example message as Vec<u8>
    let message = b"Hello, AES-256-GCM encryption!".to_vec();
    let nonce: [u8; 12] = rand::random();

    // Encryption
    let cipher = Ciphertext::encrypt_with_nonce(&message, &receiver_pk, &sender_sk, nonce).unwrap();

    // Decryption
    let decryption = cipher.decrypt(&receiver_sk).unwrap();
    assert_eq!(message, decryption.as_bytes());

    let cipher_words = cipher.as_words();
    let cipher_from_words = Ciphertext::from_words(&cipher_words);
    let decrypted_from_words = cipher_from_words.decrypt(&receiver_sk).unwrap();
    assert_eq!(message, decrypted_from_words.as_bytes());
}
