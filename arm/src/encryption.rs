use crate::utils::{bytes_to_words, words_to_bytes};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
pub use k256::AffinePoint;
use k256::{
    elliptic_curve::{group::GroupEncoding, Field},
    ProjectivePoint, Scalar,
};
use rand::rngs::OsRng;
#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, Error, NifResult, OwnedBinary, Term};
#[cfg(feature = "nif")]
use std::io::Write;
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

#[cfg(feature = "nif")]
fn do_encode<'a>(secret_key: &SecretKey, env: Env<'a>) -> Result<Term<'a>, Error> {
    let bytes = bincode::serialize(&secret_key.0).unwrap();

    let mut erl_bin = OwnedBinary::new(bytes.len()).ok_or(Error::BadArg)?;
    let _ = erl_bin.as_mut_slice().write_all(&bytes);

    Ok(erl_bin.release(env).to_term(env))
}

#[cfg(feature = "nif")]
impl Encoder for SecretKey {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let result = do_encode(self, env).expect("failed to encode SecretKey");
        result
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for SecretKey {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let binary = term.decode_as_binary()?.as_slice();
        let scalar: Scalar = bincode::deserialize(binary).expect("failed to decode SecretKey");
        Ok(SecretKey(scalar))
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
            bincode::deserialize(self.inner()).expect("deserialization failure");
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

    let cipher_words = cipher.as_words();
    let cipher_from_words = Ciphertext::from_words(&cipher_words);
    let decrypted_from_words = cipher_from_words.decrypt(&receiver_sk).unwrap();
    assert_eq!(message, decrypted_from_words);
}
