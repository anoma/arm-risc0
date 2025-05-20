use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use k256::{
    elliptic_curve::{group::GroupEncoding, Field},
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn encrypt(
        message: &Vec<u8>,
        receiver_pk: &AffinePoint,
        sender_sk: &SecretKey,
        nonce: [u8; 12],
    ) -> Self {
        // Generate the secret key using Diffie-Hellman exchange
        let inner_secret_key = InnerSecretKey::from_dh_exchange(receiver_pk, sender_sk.inner());

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&inner_secret_key.inner());

        // Encrypt with AES-256-GCM
        let cipher = aes_gcm
            .encrypt(&nonce.into(), message.as_ref())
            .expect("encryption failure");

        let pk = generate_public_key(sender_sk.inner());
        let cipher = InnerCiphert { cipher, nonce, pk };
        Self(bincode::serialize(&cipher).expect("serialization failure"))
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Vec<u8>, aes_gcm::Error> {
        if self.inner().is_empty() {
            return Err(aes_gcm::Error);
        }
        let cipher: InnerCiphert =
            bincode::deserialize(&self.inner()).expect("deserialization failure");
        // Generate the secret key using Diffie-Hellman exchange
        let inner_secret_key = InnerSecretKey::from_dh_exchange(&cipher.pk, sk.inner());

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&inner_secret_key.inner());

        // Decrypt with AES-256-GCM
        aes_gcm.decrypt(&cipher.nonce.into(), cipher.cipher.as_ref())
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

impl InnerSecretKey {
    pub fn from_dh_exchange(pk: &AffinePoint, sk: &Scalar) -> Self {
        let pk = ProjectivePoint::from(*pk);
        let shared_point = pk * sk;
        let key_bytes = shared_point.to_bytes().to_vec();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
        InnerSecretKey(*key)
    }

    pub fn inner(&self) -> Key<Aes256Gcm> {
        self.0
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
    let cipher = Ciphertext::encrypt(&message, &receiver_pk, &sender_sk, nonce);

    // Decryption
    let decryption = cipher.decrypt(&receiver_sk).unwrap();

    assert_eq!(message, decryption);
}
