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
/// The proof of the [SigmaProtocol]
pub struct SigmaProof {
    /// The sigmabus commitment.
    pub commitment_to_witness: Digest,
    /// The non-interactive sigma challenge.
    pub challenge: Scalar,
    /// The first response of the prover.
    pub response1: Vec<Scalar>,
    /// The second response of the prover.
    pub response2: Scalar,
}

/// The private inputs of the prover of the [SigmaProtocol].
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaWitness {
    /// Scalars (message vector) committed in the Delta
    pub mcv: Vec<Scalar>,
    /// Randomness used in the delta commitment
    pub rcv: Scalar,
    /// Blindings for the committed scalars
    pub blinding_mcv: Vec<Scalar>,
    /// Blinding for the delta randomness
    pub blinding_rcv: Scalar,
    /// Sigmabus salt
    pub salt: [u8; 32],
}

impl SigmaWitness {
    /// Creates a witness from the passed committed messages `mcv` and
    /// the commitment randomness `rcv`.
    /// Blindings and salt are randomly generated at each invocation.
    pub fn new(mcv: &[Scalar], rcv: &Scalar) -> SigmaWitness {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        let blinding_mcv: Vec<Scalar> = (0..mcv.len()).map(|_| Scalar::random(&mut rng)).collect();
        let blinding_rcv = Scalar::random(&mut rng);

        SigmaWitness {
            mcv: mcv.to_vec(),
            rcv: *rcv,
            blinding_mcv,
            blinding_rcv,
            salt,
        }
    }

    /// Commits the entire witness by producing a salted digest.
    pub fn commit(&self) -> Digest {
        // TODO: domain separation.
        let mut bytes: Vec<u8> = self
            .mcv
            .iter()
            .chain(self.blinding_mcv.iter())
            .flat_map(|y| y.to_bytes())
            .collect();
        bytes.extend_from_slice(&self.rcv.to_bytes());
        bytes.extend_from_slice(&self.blinding_rcv.to_bytes());
        bytes.extend_from_slice(&self.salt);

        *Impl::hash_bytes(&bytes)
    }

    /// The first response.
    pub fn first_response(
        mcv: &[Scalar],
        blinding_mcv: &[Scalar],
        challenge: &Scalar,
    ) -> Result<Vec<Scalar>, ArmError> {
        if mcv.len() != blinding_mcv.len() {
            return Err(ArmError::InvalidMcv);
        }
        Ok(Self::compute_response(mcv, blinding_mcv, challenge))
    }

    /// The second response.
    pub fn second_response(rcv: &Scalar, blinding_rcv: &Scalar, challenge: &Scalar) -> Scalar {
        *Self::compute_response(&[*rcv], &[*blinding_rcv], challenge)
            .first()
            .unwrap()
    }

    // Compute the first or second responses.
    fn compute_response(
        witness: &[Scalar],
        blinding: &[Scalar],
        challenge: &Scalar,
    ) -> Vec<Scalar> {
        // Sanity check. This assertion should never fail.
        assert!(witness.len() == blinding.len(), "length mismatch");

        witness
            .iter()
            .zip(blinding.iter())
            .map(|(w, b)| b + challenge * w)
            .collect()
    }
}

/// A Sigma protocol to prove/verify knowledge of a vector of messages committed with Pedersen.
/// The witness is the vector of messages and the commitment randomness.
/// The instance is the vector Pedersen commitment (the delta).
pub struct SigmaProtocol {
    pcs: PedersenCommitmentScheme,
}

impl SigmaProtocol {
    /// Instantiates the sigma protocol with the passed message length
    pub fn new(message_length: usize) -> Self {
        SigmaProtocol {
            pcs: PedersenCommitmentScheme { message_length },
        }
    }
    /// Non-interactive prover
    pub fn prove(
        &self,
        delta: &ProjectivePoint,
        witness: &SigmaWitness,
    ) -> Result<SigmaProof, ArmError> {
        if witness.mcv.len() != self.pcs.message_length {
            return Err(ArmError::ProveFailed("Bad sigma witness format".into()));
        }
        let first_message = self
            .pcs
            .commit(&witness.blinding_mcv, &witness.blinding_rcv);
        let commitment_to_witness = witness.commit();
        let challenge = self.generate_challenge(delta, &first_message, &commitment_to_witness);
        let response1 =
            SigmaWitness::first_response(&witness.mcv, &witness.blinding_mcv, &challenge)?;
        let response2 =
            SigmaWitness::second_response(&witness.rcv, &witness.blinding_rcv, &challenge);

        Ok(SigmaProof {
            commitment_to_witness,
            challenge,
            response1,
            response2,
        })
    }

    /// Non-interactive verifier.
    pub fn verify(&self, delta: &ProjectivePoint, proof: &SigmaProof) -> Result<(), ArmError> {
        if proof.response1.len() != self.pcs.message_length {
            return Err(ArmError::ProofVerificationFailed(
                "Bad sigma proof format".into(),
            ));
        }
        let first_message =
            self.pcs.commit(&proof.response1, &proof.response2) + *delta * (-proof.challenge);
        if proof.challenge
            != self.generate_challenge(delta, &first_message, &proof.commitment_to_witness)
        {
            return Err(ArmError::ProofVerificationFailed(
                "Sigma test failed".into(),
            ));
        }

        Ok(())
    }

    /// Used by both, prover and verifier.
    fn generate_challenge(
        &self,
        delta: &ProjectivePoint,
        first_message: &ProjectivePoint,
        commitment_to_witness: &Digest,
    ) -> Scalar {
        let mut bytes = Vec::new();
        for binding_generator in self.pcs.binding_generators().iter() {
            bytes.extend_from_slice(binding_generator.to_encoded_point(true).as_bytes());
        }
        bytes.extend_from_slice(
            PedersenCommitmentScheme::hiding_generator()
                .to_encoded_point(true)
                .as_bytes(),
        );
        bytes.extend_from_slice(delta.to_encoded_point(true).as_bytes());
        bytes.extend_from_slice(first_message.to_encoded_point(true).as_bytes());
        bytes.extend_from_slice(commitment_to_witness.as_bytes());

        crate::resource::hash_to_scalar(&bytes)
    }
}

pub struct PedersenCommitmentScheme {
    message_length: usize,
}

impl PedersenCommitmentScheme {
    /// Instantiates the scheme with the passed message length
    pub fn new(message_length: usize) -> Self {
        PedersenCommitmentScheme { message_length }
    }

    /// Commits to vector `message` using as randomness `rnd`.
    // TODO: Handle panic.
    pub fn commit(&self, message: &[Scalar], rnd: &Scalar) -> ProjectivePoint {
        assert_eq!(message.len(), self.message_length);
        let binding = message.iter().zip(self.binding_generators().iter()).fold(
            ProjectivePoint::IDENTITY,
            |acc, message_generator| {
                let message = message_generator.0;
                let generator = message_generator.1;
                acc + generator * message
            },
        );
        binding + Self::hiding_generator() * rnd
    }

    /// Publicly-verifiable binding generators.
    /// Computed via hashing to the curve.
    pub fn binding_generators(&self) -> Vec<ProjectivePoint> {
        // TODO: Handle error.
        (0..self.message_length)
            .map(|i| {
                <Secp256k1 as k256::elliptic_curve::hash2curve::GroupDigest>::hash_from_bytes::<
                    ExpandMsgXmd<Sha256Type>,
                >(
                    &[format!("BINDING_GENERATOR_DELTA_{:?}", i).as_bytes()],
                    &["CURVE_XMD:SHA-256_SSWU_RO_".as_bytes()],
                )
                .unwrap()
            })
            .collect()
    }

    pub fn hiding_generator() -> ProjectivePoint {
        ProjectivePoint::GENERATOR
    }
}
