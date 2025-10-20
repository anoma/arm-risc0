use k256::ecdsa::{Error, RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{
    elliptic_curve::PublicKey, elliptic_curve::ScalarPrimitive, ProjectivePoint, Scalar, SecretKey,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use serde_bytes::ByteArray;
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.DeltaProof"))]
pub struct DeltaProof {
    #[serde(
        deserialize_with = "deserialize_signature",
        serialize_with = "serialize_signature"
    )]
    pub signature: Signature,
    #[serde(
        deserialize_with = "deserialize_recovery_id",
        serialize_with = "serialize_recovery_id"
    )]
    pub recid: RecoveryId,
}

fn serialize_signature<S>(t: &Signature, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ByteArray::<64>::new(t.to_bytes().into()).serialize(s)
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let b: [u8; 64] = ByteArray::deserialize(deserializer)?.into_array();
    Signature::from_bytes(&b.into()).map_err(de::Error::custom)
}

fn serialize_recovery_id<S>(t: &RecoveryId, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u8(t.to_byte())
}

fn deserialize_recovery_id<'de, D>(d: D) -> Result<RecoveryId, D::Error>
where
    D: Deserializer<'de>,
{
    let s: u8 = de::Deserialize::deserialize(d)?;
    RecoveryId::try_from(s).map_err(de::Error::custom)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.DeltaWitness"))]
pub struct DeltaWitness {
    #[serde(
        deserialize_with = "deserialize_signing_key",
        serialize_with = "serialize_signing_key"
    )]
    pub signing_key: SigningKey,
}

fn serialize_signing_key<S>(t: &SigningKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ByteArray::<32>::new(t.to_bytes().into()).serialize(s)
}

fn deserialize_signing_key<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
where
    D: Deserializer<'de>,
{
    let b: [u8; 32] = ByteArray::deserialize(deserializer)?.into_array();
    SigningKey::from_bytes(&b.into()).map_err(de::Error::custom)
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
        bytes[64] = self.recid.to_byte() + 27;
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> DeltaProof {
        DeltaProof {
            signature: Signature::from_bytes((&bytes[0..64]).into()).unwrap(),
            recid: RecoveryId::from_byte(bytes[64] - 27).unwrap(),
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

    pub fn from_bytes_vec(keys: &[Vec<u8>]) -> DeltaWitness {
        let witnesses: Vec<DeltaWitness> = keys
            .iter()
            .map(|key| DeltaWitness::from_bytes(key))
            .collect();
        DeltaWitness::compress(&witnesses)
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

    pub fn compress(witnesses: &[DeltaWitness]) -> DeltaWitness {
        let mut sum = witnesses[0].clone();
        for witness in witnesses.iter().skip(1) {
            sum = sum.compose(witness);
        }
        sum
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
