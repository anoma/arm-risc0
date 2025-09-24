use crate::error::ArmError;
use risc0_zkvm::{
    default_prover, sha::Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde::{de::DeserializeOwned, Serialize};

// It takes a proving key and a witness, and returns the proof and the instance
pub fn prove<T: Serialize>(
    proving_key: &[u8],
    witness: &T,
) -> Result<(Vec<u8>, Vec<u8>), ArmError> {
    let receipt = prove_inner(witness, proving_key)?;

    let proof = bincode::serialize(&receipt.inner).map_err(|_| ArmError::SerializationError)?;
    let instance = receipt.journal.bytes;
    Ok((proof, instance))
}

// Receipt contains the proof and the public inputs
pub fn verify(verifying_key: &Digest, instance: &[u8], proof: &[u8]) -> Result<(), ArmError> {
    let inner: InnerReceipt =
        bincode::deserialize(proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;
    let receipt = Receipt::new(inner, instance.to_vec());

    receipt.verify(*verifying_key).map_err(|err| {
        ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
    })
}

pub fn journal_to_instance<T: DeserializeOwned>(journal: &[u8]) -> Result<T, ArmError> {
    let journal = risc0_zkvm::Journal {
        bytes: journal.to_vec(),
    };
    journal.decode().map_err(|_| ArmError::JournalDecodingError)
}

// Encode the seal of the given proof for use with EVM smart contract verifiers.
pub fn encode_seal(proof: &[u8]) -> Result<Vec<u8>, ArmError> {
    let inner: InnerReceipt =
        bincode::deserialize(proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;
    let seal = match inner {
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => Err(ArmError::UnsupportedProofType)?,
    };
    Ok(seal)
}

fn prove_inner<T: Serialize>(witness: &T, proving_key: &[u8]) -> Result<Receipt, ArmError> {
    let env = ExecutorEnv::builder()
        .write(witness)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .build()
        .map_err(|_| ArmError::BuildProverEnvFailed)?;

    #[cfg(feature = "fast_prover")]
    let prover_opts = ProverOpts::fast(); // Fastest, linear size, no recursion.

    #[cfg(all(not(feature = "fast_prover"), feature = "composite_prover"))]
    let prover_opts = ProverOpts::composite(); // Composite receipts, linear size, supports recursion.

    #[cfg(all(
        not(feature = "fast_prover"),
        not(feature = "composite_prover"),
        feature = "groth16_prover"
    ))]
    let prover_opts = ProverOpts::groth16(); // Groth16 receipts, constant size, blockchain-friendly.

    // If no specific prover feature is enabled, default to succinct prover.
    #[cfg(all(
        not(feature = "fast_prover"),
        not(feature = "composite_prover"),
        not(feature = "groth16_prover")
    ))]
    let prover_opts = ProverOpts::succinct(); // Succinct receipts, constant size.

    let prove_info = default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), proving_key, &prover_opts)
        .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?;
    Ok(prove_info.receipt)
}
