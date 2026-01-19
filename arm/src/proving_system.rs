//! Proving system interface for generating and verifying proofs.

use crate::error::ArmError;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};
use serde::de::DeserializeOwned;

#[cfg(feature = "solana")]
use anchor_lang::prelude::AnchorSerialize;
#[cfg(feature = "prove")]
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
#[cfg(feature = "prove")]
use serde::Serialize;
#[cfg(feature = "solana")]
use solana_groth16_verifier::{negate_g1, Proof};
#[cfg(feature = "solana")]
use solana_verifier_router::{Seal, Selector};

/// Types of proofs supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    /// Succinct(STARK) proof type.
    Succinct,
    /// Groth16 proof type.
    Groth16,
}

/// Proves a statement given a proving key and a witness, returning the proof and the instance.
#[cfg(feature = "prove")]
pub fn prove<T: Serialize>(
    proving_key: &[u8],
    witness: &T,
    proof_type: ProofType,
) -> Result<(Vec<u8>, Vec<u8>), ArmError> {
    let receipt = prove_inner(witness, proving_key, proof_type)?;

    let proof = bincode::serialize(&receipt.inner).map_err(|_| ArmError::SerializationError)?;
    let instance = receipt.journal.bytes;
    Ok((proof, instance))
}

/// Verifies a proof against the given verifying key and instance.
pub fn verify(verifying_key: &Digest, instance: &[u8], proof: &[u8]) -> Result<(), ArmError> {
    let inner: InnerReceipt =
        bincode::deserialize(proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;
    let receipt = Receipt::new(inner, instance.to_vec());

    receipt.verify(*verifying_key).map_err(|err| {
        ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
    })
}

/// Converts a serialized journal into an instance of the specified type.
pub fn journal_to_instance<T: DeserializeOwned>(journal: &[u8]) -> Result<T, ArmError> {
    let journal = risc0_zkvm::Journal {
        bytes: journal.to_vec(),
    };
    journal.decode().map_err(|_| ArmError::JournalDecodingError)
}

/// Encode the seal of the given proof for use with EVM smart contract verifiers.
pub fn encode_seal(proof: &[u8]) -> Result<Vec<u8>, ArmError> {
    let inner: InnerReceipt =
        bincode::deserialize(proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;
    let seal = match inner {
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            #[cfg(feature = "evm")]
            {
                // Create a new vector with the capacity to hold both selector and seal
                let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
                selector_seal.extend_from_slice(selector);
                selector_seal.extend_from_slice(receipt.seal.as_ref());
                selector_seal
            }

            #[cfg(feature = "solana")]
            {
                let proof_raw = receipt.seal;
                let mut proof = Proof {
                    pi_a: proof_raw[0..64].try_into().unwrap(),
                    pi_b: proof_raw[64..192].try_into().unwrap(),
                    pi_c: proof_raw[192..256].try_into().unwrap(),
                };
                proof.pi_a = negate_g1(&proof.pi_a);
                let seal = Seal {
                    selector: selector.try_into().unwrap(),
                    proof: proof,
                };
                seal.try_to_vec().unwrap()
            }
        }
        _ => Err(ArmError::UnsupportedProofType)?,
    };
    Ok(seal)
}

/// Internal function to prove a statement using the given witness and proving key.
#[cfg(feature = "prove")]
fn prove_inner<T: Serialize>(
    witness: &T,
    proving_key: &[u8],
    proof_type: ProofType,
) -> Result<Receipt, ArmError> {
    let env = ExecutorEnv::builder()
        .write(witness)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .build()
        .map_err(|_| ArmError::BuildProverEnvFailed)?;

    let prover_opts = match proof_type {
        ProofType::Succinct => {
            ProverOpts::succinct() // Succinct receipts, constant size.
        }
        ProofType::Groth16 => {
            ProverOpts::groth16() // Groth16 receipts, constant size, blockchain-friendly.
        }
    };

    let prove_info = default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), proving_key, &prover_opts)
        .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?;
    Ok(prove_info.receipt)
}
