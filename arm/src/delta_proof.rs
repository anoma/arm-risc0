//! Host-engine delta operations: k256 signing, recovery-based verification,
//! and witness composition. The proof and witness types themselves are
//! structured bytes in `anoma-rm-core` (re-exported here unchanged); this
//! module converts them to k256 working values at its boundary.

pub use arm_core::delta_proof::*;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{
    elliptic_curve::{PublicKey, ScalarPrimitive},
    ProjectivePoint, Scalar, SecretKey,
};

use crate::error::ArmError;
use sha3::{Digest, Keccak256};

/// The delta instance contains the verifying key and the message used to
/// verify the delta proof. A host-side working value — never on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaInstance {
    /// The verifying key.
    pub verifying_key: VerifyingKey,
    /// The message that was signed.
    pub message: Vec<u8>,
}

impl DeltaInstance {
    /// Creates a delta instance from a list of projective points and the signed message.
    pub fn new(deltas: &[ProjectivePoint], message: Vec<u8>) -> Result<DeltaInstance, ArmError> {
        let sum = deltas
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let pk = PublicKey::from_affine(sum.to_affine()).map_err(|_| ArmError::InvalidPublicKey)?;
        let vk = VerifyingKey::from(&pk);
        Ok(DeltaInstance {
            verifying_key: vk,
            message,
        })
    }
}

/// The witness's signing key as a k256 working value.
fn signing_key(witness: &DeltaWitness) -> Result<SigningKey, ArmError> {
    SigningKey::from_slice(witness.as_bytes()).map_err(|_| ArmError::InvalidSigningKey)
}

/// Generates a delta proof by signing the given message with the provided witness.
pub fn prove(message: &[u8], witness: &DeltaWitness) -> Result<DeltaProof, ArmError> {
    // Hash the message using Keccak256
    let mut digest = Keccak256::new();
    digest.update(message);

    // Sign the hashed message using RFC6979
    let (signature, recid) = signing_key(witness)?
        .sign_digest_recoverable(digest)
        .map_err(|_| ArmError::DeltaProofGenerationFailed)?;

    // On-chain signatures are not supported when recid is 2 or 3.
    if recid.to_byte() > 1 {
        return Err(ArmError::InvalidDeltaProof);
    }

    Ok(DeltaProof {
        signature: signature.to_bytes().into(),
        recovery_id: recid.to_byte(),
    })
}

/// Verifies the delta proof against the instance (which carries the message).
pub fn verify(proof: &DeltaProof, instance: &DeltaInstance) -> Result<(), ArmError> {
    // Construction already bounds the recovery id, and the low-s check is
    // the shared byte logic in core.
    proof.check_low_s()?;

    let signature =
        Signature::from_bytes((&proof.signature).into()).map_err(|_| ArmError::InvalidSignature)?;
    let recid = RecoveryId::from_byte(proof.recovery_id).ok_or(ArmError::InvalidDeltaProof)?;

    // Hash the message using Keccak256
    let mut digest = Keccak256::new();
    digest.update(&instance.message);

    // Verify the signature
    let vk = VerifyingKey::recover_from_digest(digest, &signature, recid)
        .map_err(|_| ArmError::DeltaProofVerificationFailed)?;
    if vk != instance.verifying_key {
        return Err(ArmError::DeltaProofVerificationFailed);
    }
    Ok(())
}

/// Creates a delta witness from a list of secret-key scalars by summing them up.
pub fn from_scalars(secret_keys: &[Scalar]) -> Result<DeltaWitness, ArmError> {
    if secret_keys.is_empty() {
        return Err(ArmError::EmptyDeltaWitnesses);
    }
    let sum = secret_keys.iter().fold(Scalar::ZERO, |acc, x| acc + x);
    witness_from_scalar(sum)
}

/// Creates a delta witness from a list of byte vectors representing secret keys.
pub fn from_bytes_vec(keys: &[Vec<u8>]) -> Result<DeltaWitness, ArmError> {
    let witnesses: Vec<DeltaWitness> = keys
        .iter()
        .map(|key| DeltaWitness::from_bytes(key))
        .collect::<Result<_, _>>()?;
    compress(&witnesses)
}

/// Composes two delta witnesses by summing their signing-key scalars.
pub fn compose(a: &DeltaWitness, b: &DeltaWitness) -> Result<DeltaWitness, ArmError> {
    let sum = *signing_key(a)?.as_nonzero_scalar().as_ref()
        + *signing_key(b)?.as_nonzero_scalar().as_ref();
    witness_from_scalar(sum)
}

/// Compresses a list of delta witnesses into a single delta witness by summing them up.
pub fn compress(witnesses: &[DeltaWitness]) -> Result<DeltaWitness, ArmError> {
    let (first, rest) = witnesses
        .split_first()
        .ok_or(ArmError::EmptyDeltaWitnesses)?;
    rest.iter()
        .try_fold(first.clone(), |acc, w| compose(&acc, w))
}

fn witness_from_scalar(scalar: Scalar) -> Result<DeltaWitness, ArmError> {
    let primitive: ScalarPrimitive<_> = scalar.into();
    // Round-trip through SecretKey so a zero sum is rejected the same way
    // the k256-typed predecessor rejected it.
    let sk =
        SecretKey::from_slice(&primitive.to_bytes()).map_err(|_| ArmError::InvalidSigningKey)?;
    DeltaWitness::from_bytes(&sk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;

    fn random_witness() -> DeltaWitness {
        let signing_key = SigningKey::random(&mut OsRng);
        DeltaWitness::from_bytes(&signing_key.to_bytes()).unwrap()
    }

    #[test]
    fn test_delta_proof() {
        let witness = random_witness();
        let verifying_key = *signing_key(&witness).unwrap().verifying_key();

        let message = b"Hello, world!".to_vec();
        let proof = prove(&message, &witness).unwrap();
        let instance = DeltaInstance {
            verifying_key,
            message,
        };

        verify(&proof, &instance).unwrap();
    }

    /// DeltaProof: serialize then deserialize via bincode must round-trip.
    #[test]
    fn delta_proof_bincode_roundtrip() {
        let proof = prove(b"roundtrip", &random_witness()).unwrap();

        let encoded = bincode::serialize(&proof).unwrap();
        let decoded: DeltaProof = bincode::deserialize(&encoded).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn empty_delta_witness_inputs_are_rejected() {
        assert_eq!(from_scalars(&[]), Err(ArmError::EmptyDeltaWitnesses));
        assert_eq!(from_bytes_vec(&[]), Err(ArmError::EmptyDeltaWitnesses));
        assert_eq!(compress(&[]), Err(ArmError::EmptyDeltaWitnesses));
    }

    /// DeltaWitness: serialize then deserialize via bincode must round-trip.
    #[test]
    fn delta_witness_bincode_roundtrip() {
        let witness = random_witness();

        let encoded = bincode::serialize(&witness).unwrap();
        let decoded: DeltaWitness = bincode::deserialize(&encoded).unwrap();
        assert_eq!(witness, decoded);
    }

    /// The core byte checks and k256 must agree on validity: any witness
    /// bytes core accepts, k256 parses, and vice versa (spot boundaries).
    #[test]
    fn core_scalar_range_matches_k256() {
        let cases: [[u8; 32]; 4] = [[0u8; 32], [0x11u8; 32], SECP256K1_ORDER, [0xffu8; 32]];
        for bytes in cases {
            let core_ok = DeltaWitness::from_bytes(&bytes).is_ok();
            let k256_ok = SigningKey::from_slice(&bytes).is_ok();
            assert_eq!(core_ok, k256_ok, "disagreement on {bytes:02x?}");
        }
        let mut n_minus_one = SECP256K1_ORDER;
        n_minus_one[31] -= 1;
        assert_eq!(
            DeltaWitness::from_bytes(&n_minus_one).is_ok(),
            SigningKey::from_slice(&n_minus_one).is_ok()
        );
    }

    /// The core low-s boundary and k256's IsHigh must agree.
    #[test]
    fn core_low_s_matches_k256() {
        use k256::elliptic_curve::scalar::IsHigh;
        for _ in 0..64 {
            let proof = prove(b"low-s agreement", &random_witness()).unwrap();
            let signature = Signature::from_bytes((&proof.signature).into()).unwrap();
            let k256_high: bool = signature.s().is_high().into();
            let core_high = proof.check_low_s().is_err();
            assert_eq!(core_high, k256_high);
            // prove() normalizes via RFC6979 + recid<=1, so both must be low.
            assert!(!core_high);
        }
    }
}
