use aes_gcm::{Aes256Gcm, KeyInit, Key, Nonce}; // AES-256-GCM authentication
use aes_gcm::aead::Aead;
use k256::{ProjectivePoint, Scalar}; // Add serde import
use k256::EncodedPoint;
use rand::thread_rng;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::sec1::FromEncodedPoint;

#[derive(Debug, Clone)]
pub struct Ciphertext(Vec<u8>);

#[derive(Debug, Clone)]
pub struct SecretKey([u8; 32]);

impl Ciphertext {
    pub fn encrypt(message: &Vec<u8>, pk: &ProjectivePoint, sk: &Scalar, encrypt_nonce: &[u8; 32]) -> Self {
        // Generate the secret key using Diffie-Hellman exchange
        let secret_key = SecretKey::from_dh_exchange(pk, sk);

        // Derive AES-256 key and nonce
        let aes_key = secret_key.derive_key();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(&encrypt_nonce[..12]);

        // Encrypt with AES-256-GCM
        let ciphertext = cipher.encrypt(nonce, message.as_ref())
            .expect("encryption failure");

        Ciphertext(ciphertext)
    }

    pub fn decrypt(&self, sk: &Scalar, pk: &ProjectivePoint, encrypt_nonce: &[u8; 32]) -> Option<Vec<u8>> {
        // Generate the secret key using Diffie-Hellman exchange
        let secret_key = SecretKey::from_dh_exchange(pk, sk);

        // Derive AES-256 key and nonce
        let aes_key = secret_key.derive_key();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(&encrypt_nonce[..12]);

        // Decrypt with AES-256-GCM
        let plaintext_bytes = cipher.decrypt(nonce, self.0.as_ref()).ok()?;
        Some(plaintext_bytes)
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl SecretKey {
    pub fn from_dh_exchange(pk: &ProjectivePoint, sk: &Scalar) -> Self {
        let shared_point = pk * sk;
        let shared_point_encoded = EncodedPoint::from(shared_point.to_affine());
        let key_bytes: [u8; 32] = shared_point_encoded.as_bytes()[..32].try_into().unwrap();
        SecretKey(key_bytes)
    }

    pub fn derive_key(&self) -> [u8; 32] {
        self.0
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(input_vec: Vec<u8>) -> Self {
        Ciphertext(
            input_vec
        )
    }
}

pub fn generate_public_key(sk: &Scalar) -> ProjectivePoint {
    // Compute public key as generator * private key
    ProjectivePoint::GENERATOR * sk
}

/// Generates a random private key (Scalar) and its corresponding public key (ProjectivePoint)
pub fn random_keypair() -> (Scalar, ProjectivePoint) {
    // Generate random private key
    let sk = Scalar::random(&mut thread_rng());
    let pk = generate_public_key(&sk);

    (sk, pk)
    
}

/// Converts a ProjectivePoint to bytes for serialization
pub fn projective_point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
    let affine = point.to_affine();
    let encoded = EncodedPoint::from(affine);
    encoded.as_bytes().to_vec()
}

/// Converts bytes back to a ProjectivePoint, returning None if invalid
pub fn bytes_to_projective_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let ret = EncodedPoint::from_bytes(bytes)
        .ok()
        .and_then(|encoded| Option::from(ProjectivePoint::from_encoded_point(&encoded)));
    ret
}


#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, EncodedPoint, Scalar};
    pub use rand::rngs::OsRng;
    #[test]
    fn test_encryption() {
        // Key generation
        let sender_sk = Scalar::generate_vartime(&mut OsRng); // Generate a random sender's private key
        let pk = ProjectivePoint::GENERATOR * sender_sk; // Generate the corresponding public key

        // Example message and nonce
        let message = b"Hello, AES-256-GCM encryption!".to_vec(); // Example message as Vec<u8>
        let encrypt_nonce = [0u8; 32]; // Example nonce as [u8; 32] (all zeros for simplicity)

        // Encryption
        let cipher = Ciphertext::encrypt(&message, &pk, &sender_sk, &encrypt_nonce);

        // Decryption
        let decryption = cipher.decrypt(&sender_sk, &pk, &encrypt_nonce).unwrap();

        // Verify the decrypted message matches the original
        assert_eq!(message, decryption);
    }



    #[test]
    fn test_projective_point_to_bytes() {
        // Generate an example projective point using the generator point
        let original_point = ProjectivePoint::GENERATOR;

        // Convert the projective point to bytes
        let encoded_point: EncodedPoint = original_point.to_affine().into();
        let bytes = encoded_point.as_bytes();

        // Convert bytes back to a ProjectivePoint
        let reconstructed_point = bytes_to_projective_point(&bytes.to_vec())
            .expect("Failed to convert bytes back to ProjectivePoint");

        // Verify that the original point and the reconstructed point are equal
        assert_eq!(original_point, reconstructed_point);
    }
}
