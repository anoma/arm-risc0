// Implementes the sigma protocol of the sigmabus technique of this paper https://eprint.iacr.org/2023/1406
// adjusted to our setting.
use crate::{compliance::TX_MAX_RESOURCES, error::ArmError};
use k256::{
    elliptic_curve::{
        hash2curve::ExpandMsgXmd,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
};
use rand::RngCore;
use risc0_zkvm::{
    sha::{rust_crypto::Sha256 as Sha256Type, Impl, Sha256},
    Digest,
};

/// The proof of the [SigmaProtocol]
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaProof {
    /// The prover's first message.
    pub first_message: EncodedPoint,
    /// The sigmabus commitment.
    pub commitment_to_witness: Digest,
    /// The non-interactive sigma challenge.
    pub challenge: Scalar,
    /// The first response of the prover.
    pub response1: Vec<Scalar>,
    /// The second response of the prover.
    pub response2: Scalar,
}

impl SigmaProof {
    pub fn from_first_message_and_sigmaproof_short(
        first_message: &EncodedPoint,
        sps: &SigmaProofShort,
    ) -> Self {
        SigmaProof {
            first_message: first_message.clone(),
            commitment_to_witness: sps.commitment_to_witness,
            challenge: sps.challenge,
            response1: sps.response1.clone(),
            response2: sps.response2,
        }
    }
}

/// Skips the first message.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigmaProofShort {
    /// The sigmabus commitment.
    pub commitment_to_witness: Digest,
    /// The non-interactive sigma challenge.
    pub challenge: Scalar,
    /// The first response of the prover.
    pub response1: Vec<Scalar>,
    /// The second response of the prover.
    pub response2: Scalar,
}

impl SigmaProofShort {
    pub fn from_sigmaproof(sp: &SigmaProof) -> Self {
        SigmaProofShort {
            commitment_to_witness: sp.commitment_to_witness,
            challenge: sp.challenge,
            response1: sp.response1.clone(),
            response2: sp.response2,
        }
    }
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
pub struct SigmaProtocol;

impl SigmaProtocol {
    /// Non-interactive prover
    pub fn prove(delta: &EncodedPoint, witness: &SigmaWitness) -> Result<SigmaProof, ArmError> {
        if witness.mcv.len() != PedersenCommitmentScheme::MESSAGE_LENGTH {
            return Err(ArmError::ProveFailed("Bad sigma witness format".into()));
        }
        let first_message =
            PedersenCommitmentScheme::commit(&witness.blinding_mcv, &witness.blinding_rcv)
                .to_encoded_point(true);
        let commitment_to_witness = witness.commit();
        let challenge = Self::generate_challenge(&delta, &first_message, &commitment_to_witness);
        let response1 =
            SigmaWitness::first_response(&witness.mcv, &witness.blinding_mcv, &challenge)?;
        let response2 =
            SigmaWitness::second_response(&witness.rcv, &witness.blinding_rcv, &challenge);

        Ok(SigmaProof {
            first_message,
            commitment_to_witness,
            challenge,
            response1,
            response2,
        })
    }

    /// Non-interactive verifier.
    pub fn verify(delta: &ProjectivePoint, proof: &SigmaProof) -> Result<(), ArmError> {
        if proof.response1.len() != PedersenCommitmentScheme::MESSAGE_LENGTH {
            return Err(ArmError::ProofVerificationFailed(
                "Bad message length".into(),
            ));
        }

        if proof.challenge
            != Self::generate_challenge(
                &delta.to_encoded_point(true),
                &proof.first_message,
                &proof.commitment_to_witness,
            )
        {
            return Err(ArmError::ProofVerificationFailed("Bad challenge".into()));
        }

        let first_message = ProjectivePoint::from_encoded_point(&proof.first_message)
            .into_option()
            .ok_or(ArmError::ProofVerificationFailed(
                "Bad first message format".into(),
            ))?;

        if first_message + *delta * proof.challenge
            != PedersenCommitmentScheme::commit(&proof.response1, &proof.response2)
        {
            return Err(ArmError::ProofVerificationFailed(
                "Sigma verifier test failed".into(),
            ));
        }

        Ok(())
    }

    /// Verifies a batch of statements/proofs. Batch-verification is more efficient
    /// than verifying all individually (O(m + b) vs O(mb) scalar mults, where `m` is the message length
    /// and `b` the batch length.)
    // This efficiency gain is the reason of including
    // the first message in [SigmaProof].
    pub fn batch_verify(deltas: &[ProjectivePoint], proofs: &[SigmaProof]) -> Result<(), ArmError> {
        let batch_length = if deltas.len() == proofs.len() {
            deltas.len()
        } else {
            return Err(ArmError::ProofVerificationFailed("Bad batch length".into()));
        };

        let mut first_messages = Vec::with_capacity(batch_length);
        let mut batch_bytes = Vec::new();
        for (delta, proof) in deltas.iter().zip(proofs.iter()) {
            if proof.response1.len() != PedersenCommitmentScheme::MESSAGE_LENGTH {
                return Err(ArmError::ProofVerificationFailed(
                    "Bad message length".into(),
                ));
            }

            if proof.challenge
                != Self::generate_challenge(
                    &delta.to_encoded_point(true),
                    &proof.first_message,
                    &proof.commitment_to_witness,
                )
            {
                return Err(ArmError::ProofVerificationFailed("Bad challenge".into()));
            }

            first_messages.push(
                ProjectivePoint::from_encoded_point(&proof.first_message)
                    .into_option()
                    .ok_or(ArmError::ProofVerificationFailed(
                        "Bad first message format".into(),
                    ))?,
            );

            // Collect batch bytes
            batch_bytes.extend_from_slice(delta.to_encoded_point(true).as_bytes());
            batch_bytes.extend_from_slice(proof.first_message.as_bytes());
            batch_bytes.extend_from_slice(proof.commitment_to_witness.as_bytes());
            batch_bytes.extend_from_slice(&proof.challenge.to_bytes());
            for scalar in proof.response1.iter() {
                batch_bytes.extend_from_slice(&scalar.to_bytes());
            }
            batch_bytes.extend_from_slice(&proof.response2.to_bytes());
        }

        // Generate a random linear combination via hashing the batch
        let mut chall = crate::resource::hash_to_scalar(&batch_bytes);
        let mut rlc = Vec::with_capacity(batch_length);
        rlc.push(chall);
        (1..batch_length).for_each(|_| {
            chall *= chall;
            rlc.push(chall);
        });

        // Homomorphically combine all
        let mut combined_delta = ProjectivePoint::IDENTITY;
        let mut combined_first_message = ProjectivePoint::IDENTITY;
        let mut combined_response1 = vec![Scalar::ZERO; PedersenCommitmentScheme::MESSAGE_LENGTH];
        let mut combined_response2 = Scalar::ZERO;
        deltas
            .iter()
            .zip(first_messages.iter())
            .zip(proofs.iter())
            .zip(rlc.iter())
            .for_each(|(((delta, first_message), proof), batch_chall)| {
                // The sigma challenge is also exponentiated here (so, omitted in the test below).
                combined_delta = combined_delta + *delta * (proof.challenge * batch_chall);

                combined_first_message = combined_first_message + first_message * batch_chall;

                combined_response1 = combined_response1
                    .iter_mut()
                    .zip(proof.response1.iter())
                    .map(|(cz1, z1)| {
                        *cz1 += z1 * batch_chall;
                        *cz1
                    })
                    .collect();

                combined_response2 += proof.response2 * batch_chall;
            });

        // Test the combined result
        if combined_first_message + combined_delta
            != PedersenCommitmentScheme::commit(&combined_response1, &combined_response2)
        {
            return Err(ArmError::ProofVerificationFailed(
                "Sigma verifier test failed".into(),
            ));
        }

        Ok(())
    }

    /// Used by both, prover and verifier.
    fn generate_challenge(
        delta: &EncodedPoint,
        first_message: &EncodedPoint,
        commitment_to_witness: &Digest,
    ) -> Scalar {
        let mut bytes = Vec::new();
        for binding_generator in PedersenCommitmentScheme::binding_generators().iter() {
            bytes.extend_from_slice(binding_generator.to_encoded_point(true).as_bytes());
        }
        bytes.extend_from_slice(
            PedersenCommitmentScheme::HIDING_GENERATOR
                .to_encoded_point(true)
                .as_bytes(),
        );
        bytes.extend_from_slice(delta.as_bytes());
        bytes.extend_from_slice(first_message.as_bytes());
        bytes.extend_from_slice(commitment_to_witness.as_bytes());

        crate::resource::hash_to_scalar(&bytes)
    }
}

pub struct PedersenCommitmentScheme;

impl PedersenCommitmentScheme {
    pub const HIDING_GENERATOR: ProjectivePoint = ProjectivePoint::GENERATOR;
    pub const MESSAGE_LENGTH: usize = TX_MAX_RESOURCES;

    /// Commits to vector `message` using as randomness `rnd`.
    // TODO: Handle panic.
    pub fn commit(message: &[Scalar], rnd: &Scalar) -> ProjectivePoint {
        assert_eq!(message.len(), Self::MESSAGE_LENGTH);
        let binding = message.iter().zip(Self::binding_generators().iter()).fold(
            ProjectivePoint::IDENTITY,
            |acc, message_generator| {
                let message = message_generator.0;
                let generator = message_generator.1;
                acc + generator * message
            },
        );
        binding + Self::HIDING_GENERATOR * rnd
    }

    /// Publicly-verifiable binding generators.
    /// Computed via hashing to the curve.
    pub fn binding_generators() -> Vec<ProjectivePoint> {
        // TODO: Handle error.
        (0..Self::MESSAGE_LENGTH)
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
}
