use risc0_zkvm::{
    default_prover, sha::Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde::{de::DeserializeOwned, Serialize};

// It takes a proving key and a witness, and returns the proof and the instance
pub fn prove<T: Serialize>(proving_key: &[u8], witness: &T) -> (Vec<u8>, Vec<u8>) {
    let receipt = prove_inner(witness, proving_key);

    let proof = bincode::serialize(&receipt.inner).unwrap();
    let instance = receipt.journal.bytes;
    (proof, instance)
}

// Receipt contains the proof and the public inputs
pub fn verify(verifying_key: &Digest, instance: &[u8], proof: &[u8]) -> bool {
    let inner: InnerReceipt = bincode::deserialize(proof).unwrap();
    let receipt = Receipt::new(inner, instance.to_vec());

    receipt.verify(*verifying_key).is_ok()
}

pub fn journal_to_instance<T: DeserializeOwned>(journal: &[u8]) -> T {
    let journal = risc0_zkvm::Journal {
        bytes: journal.to_vec(),
    };
    journal.decode().unwrap()
}

fn prove_inner<T: Serialize>(witness: &T, proving_key: &[u8]) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();

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

    default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), proving_key, &prover_opts)
        .unwrap()
        .receipt
}
