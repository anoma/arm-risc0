use k256::{
    elliptic_curve::{hash2curve::ExpandMsgXmd, sec1::ToEncodedPoint, Field},
    ProjectivePoint, Scalar, Secp256k1,
};
use rand::RngCore;
use risc0_zkvm::{
    sha::{rust_crypto::Sha256 as Sha256Type, Impl, Sha256},
    Digest,
};

use crate::error::ArmError;

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaProof {
    pub commitment_to_witness: Digest,
    pub challenge: Scalar,
    pub response1: Vec<Scalar>,
    pub response2: Vec<Scalar>,
}

/// The private inputs of the prover of the [SigmaProtocol].
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaWitness {
    /// Scalars (message vector) committed in the Deltas
    pub mcv: Vec<Scalar>,
    /// Randomness used in the delta commitments
    pub rcv: Vec<Scalar>,
    /// Blindings for the committed scalars
    pub blinding_mcv: Vec<Scalar>,
    /// Blinding for the delta randomness
    pub blinding_rcv: Vec<Scalar>,
    /// Sigmabus salt
    pub salt: [u8; 32],
}

impl SigmaWitness {
    /// Creates a witness from the passed committed messages `mcv` and
    /// the commitment randomness `rcv`.
    /// Blindings and salt are randomly generated at each invocation.
    pub fn new(mcv: &[Scalar], rcv: &[Scalar]) -> Result<SigmaWitness, ArmError> {
        if mcv.len() != rcv.len() {
            return Err(ArmError::InvalidMcv);
        }
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        let (blinding_mcv, blinding_rcv): (Vec<Scalar>, Vec<Scalar>) = (0..mcv.len())
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();

        Ok(SigmaWitness {
            mcv: mcv.to_vec(),
            rcv: rcv.to_vec(),
            blinding_mcv,
            blinding_rcv,
            salt,
        })
    }

    /// Commits the entire witness by producing a salted digest.
    pub fn commit(&self) -> Digest {
        // Get bytes of all witnesses. TODO: domain separation.
        let mut bytes: Vec<u8> = self
            .mcv
            .iter()
            .chain(self.rcv.iter())
            .chain(self.blinding_mcv.iter())
            .chain(self.blinding_rcv.iter())
            .flat_map(|y| y.to_bytes())
            .collect();
        bytes.extend_from_slice(&self.salt);

        *Impl::hash_bytes(&bytes)
    }

    /// The first and second responses.
    pub fn response(
        witness: &[Scalar],
        blinding: &[Scalar],
        challenge: &Scalar,
    ) -> Result<Vec<Scalar>, ArmError> {
        if witness.len() != blinding.len() {
            return Err(ArmError::InvalidMcv);
        }
        Ok(witness
            .iter()
            .zip(blinding.iter())
            .map(|(w, b)| b + challenge * w)
            .collect())
    }

    /// Pedersen commits to `message` using as randomness `rnd`.
    /// Outputs one commitment per component of the message.
    // TODO: Handle panic.
    pub fn pedersen_commit_batch(message: &[Scalar], rnd: &[Scalar]) -> Vec<ProjectivePoint> {
        assert_eq!(message.len(), rnd.len());
        message
            .iter()
            .zip(rnd.iter())
            .map(|(m, r)| {
                let bb = SigmaProtocol::binding_generator();
                let hh = SigmaProtocol::hiding_generator();
                bb * m + hh * r
            })
            .collect()
    }
}

/// A Sigma protocol to prove/verify knowledge of a batch of messages committed with Pedersen.
/// The witness is the batch of messages and the commitment randomness.
/// The instance is the batch of commitments.
pub struct SigmaProtocol;
impl SigmaProtocol {
    /// Non-interactive prover
    pub fn prove(
        deltas: &[ProjectivePoint],
        witness: &SigmaWitness,
    ) -> Result<SigmaProof, ArmError> {
        let first_message =
            SigmaWitness::pedersen_commit_batch(&witness.blinding_mcv, &witness.blinding_rcv);
        let commitment_to_witness = witness.commit();
        let challenge = Self::generate_challenge(deltas, &first_message, &commitment_to_witness);
        let response1 = SigmaWitness::response(&witness.mcv, &witness.blinding_mcv, &challenge)?;
        let response2 = SigmaWitness::response(&witness.rcv, &witness.blinding_rcv, &challenge)?;

        Ok(SigmaProof {
            commitment_to_witness,
            challenge,
            response1,
            response2,
        })
    }

    /// Non-interactive verifier.
    pub fn verify(deltas: &[ProjectivePoint], proof: &SigmaProof) -> Result<(), ArmError> {
        if proof.response1.len() != proof.response2.len() || proof.response1.len() != deltas.len() {
            return Err(ArmError::ProofVerificationFailed(
                "Bad sigma proof format".into(),
            ));
        }
        let first_message: Vec<ProjectivePoint> = (0..deltas.len())
            .map(|j| {
                Self::binding_generator() * proof.response1[j]
                    + Self::hiding_generator() * proof.response2[j]
                    + deltas[j] * (-proof.challenge)
            })
            .collect();
        if proof.challenge
            != Self::generate_challenge(deltas, &first_message, &proof.commitment_to_witness)
        {
            return Err(ArmError::ProofVerificationFailed(
                "Sigma test failed".into(),
            ));
        }

        Ok(())
    }

    /// Used by both, prover and verifier.
    fn generate_challenge(
        deltas: &[ProjectivePoint],
        first_message: &[ProjectivePoint],
        commitment_to_witness: &Digest,
    ) -> Scalar {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::binding_generator().to_encoded_point(true).as_bytes());
        bytes.extend_from_slice(Self::hiding_generator().to_encoded_point(true).as_bytes());
        for point in deltas.iter().chain(first_message) {
            bytes.extend_from_slice(point.to_encoded_point(true).as_bytes());
        }
        bytes.extend_from_slice(commitment_to_witness.as_bytes());

        crate::resource::hash_to_scalar(&bytes)
    }

    pub fn binding_generator() -> ProjectivePoint {
        // TODO: Handle error.
        <Secp256k1 as k256::elliptic_curve::hash2curve::GroupDigest>::hash_from_bytes::<
            ExpandMsgXmd<Sha256Type>,
        >(
            &["BINDING_GENERATOR_DELTAS".as_bytes()],
            &["CURVE_XMD:SHA-256_SSWU_RO_".as_bytes()],
        )
        .unwrap()
    }
    pub fn hiding_generator() -> ProjectivePoint {
        // TODO: Handle error.
        <Secp256k1 as k256::elliptic_curve::hash2curve::GroupDigest>::hash_from_bytes::<
            ExpandMsgXmd<Sha256Type>,
        >(
            &["HIDING_GENERATOR_DELTAS".as_bytes()],
            &["CURVE_XMD:SHA-256_SSWU_RO_".as_bytes()],
        )
        .unwrap()
    }
}
