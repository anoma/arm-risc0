use k256::ecdsa::{Error, RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{elliptic_curve::ScalarPrimitive, ProjectivePoint, PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug)]
pub struct DeltaProof {
    pub signature: Signature,
    pub recid: RecoveryId,
}

#[derive(Clone, Debug)]
pub struct DeltaWitness {
    pub signing_key: SigningKey,
}

pub struct DeltaInstance {
    pub verifying_key: VerifyingKey,
}

impl DeltaProof {
    pub fn prove(message: &[u8], witness: &DeltaWitness) -> DeltaProof {
        // Hash the message using Keccak256
        let mut digest = Keccak256::new();
        digest.update(message);

        // Sign the hashed message using RFC6979
        let (signature, recid) = witness
            .signing_key
            .sign_digest_recoverable(digest)
            .expect("Failed to sign message");

        DeltaProof { signature, recid }
    }

    pub fn verify(
        message: &[u8],
        proof: &DeltaProof,
        instance: DeltaInstance,
    ) -> Result<bool, Error> {
        // Hash the message using Keccak256
        let mut digest = Keccak256::new();
        digest.update(message);

        // Verify the signature
        let vk = VerifyingKey::recover_from_digest(digest, &proof.signature, proof.recid)?;
        Ok(vk == instance.verifying_key)
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..64].clone_from_slice(&self.signature.to_bytes());
        bytes[64] = self.recid.to_byte();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> DeltaProof {
        DeltaProof {
            signature: Signature::from_bytes((&bytes[0..64]).into()).unwrap(),
            recid: RecoveryId::from_byte(bytes[64]).unwrap(),
        }
    }
}

impl DeltaWitness {
    pub fn from_scalars(secret_keys: &[Scalar]) -> DeltaWitness {
        let sum: ScalarPrimitive<_> = secret_keys
            .iter()
            .fold(Scalar::ZERO, |acc, x| acc + x)
            .into();
        let sk: SecretKey = SecretKey::new(sum);
        let signing_key = SigningKey::from(&sk);
        DeltaWitness { signing_key }
    }

    pub fn from_bytes(bytes: &[u8]) -> DeltaWitness {
        DeltaWitness {
            signing_key: SigningKey::from_bytes(bytes.into()).unwrap(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn compose(&self, other: &DeltaWitness) -> Self {
        let sum = self.signing_key.as_nonzero_scalar().as_ref()
            + other.signing_key.as_nonzero_scalar().as_ref();
        let sk: SecretKey = SecretKey::new(sum.into());
        Self {
            signing_key: SigningKey::from(sk),
        }
    }
}

impl DeltaInstance {
    pub fn from_deltas(deltas: &[ProjectivePoint]) -> Result<DeltaInstance, Error> {
        let sum = deltas
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let pk = PublicKey::from_affine(sum.to_affine()).unwrap();
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
        Ok(DeltaProof::from_bytes(&bytes))
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
        Ok(DeltaWitness::from_bytes(&bytes))
    }
}

#[test]
fn test_delta_proof() {
    use k256::elliptic_curve::rand_core::OsRng;

    let mut rng = OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let message = b"Hello, world!";
    let witness = DeltaWitness { signing_key };
    let proof = DeltaProof::prove(message, &witness);
    let instance = DeltaInstance { verifying_key };

    assert!(DeltaProof::verify(message, &proof, instance).unwrap());
}
