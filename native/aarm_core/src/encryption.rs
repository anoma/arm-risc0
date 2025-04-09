use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use k256::{
    elliptic_curve::{group::GroupEncoding, Field},
    AffinePoint, ProjectivePoint, Scalar,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    // AES GCM encrypted message
    cipher: Vec<u8>,
    // 96-bits; unique per message
    nonce: [u8; 12],
    // Sender's public key
    pk: AffinePoint,
}

#[derive(Debug, Clone)]
pub struct SecretKey(Key<Aes256Gcm>);

impl Ciphertext {
    pub fn encrypt(
        message: &Vec<u8>,
        receiver_pk: &AffinePoint,
        sender_sk: &Scalar,
        nonce: [u8; 12],
    ) -> Self {
        // Generate the secret key using Diffie-Hellman exchange
        let secret_key = SecretKey::from_dh_exchange(receiver_pk, sender_sk);

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&secret_key.inner());

        // Encrypt with AES-256-GCM
        let cipher = aes_gcm
            .encrypt(&nonce.into(), message.as_ref())
            .expect("encryption failure");

        let pk = generate_public_key(sender_sk);
        Ciphertext { cipher, nonce, pk }
    }

    pub fn decrypt(&self, sk: &Scalar) -> Result<Vec<u8>, aes_gcm::Error> {
        // Generate the secret key using Diffie-Hellman exchange
        let secret_key = SecretKey::from_dh_exchange(&self.pk, sk);

        // Derive AES-256 key and nonce
        let aes_gcm = Aes256Gcm::new(&secret_key.inner());

        // Convert nonce to 96-bits
        // let nonce = Nonce::<U12>::from_slice(&self.nonce);

        // Decrypt with AES-256-GCM
        aes_gcm.decrypt(&self.nonce.into(), self.cipher.as_ref())
    }
}

impl SecretKey {
    pub fn from_dh_exchange(pk: &AffinePoint, sk: &Scalar) -> Self {
        let pk = ProjectivePoint::from(*pk);
        let shared_point = pk * sk;
        let key_bytes = shared_point.to_bytes().to_vec();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
        SecretKey(*key)
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
pub fn random_keypair() -> (Scalar, AffinePoint) {
    let sk = Scalar::random(&mut OsRng);
    let pk = generate_public_key(&sk);

    (sk, pk)
}

#[test]
fn test_encryption() {
    // Generate a random sender's private key
    let sender_sk = Scalar::generate_vartime(&mut OsRng);
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
