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

    // Defualt prover: it generates succinct receipts, which are constant size in the length of
    // execution.
    #[cfg(feature = "succinct_prover")]
    let prover_opts = ProverOpts::succinct();

    // The fastest prover options.  Receipt will be linear in length of the
    // execution, and does not support compression via recursion.
    #[cfg(feature = "fast_prover")]
    let prover_opts = ProverOpts::fast();

    // It generates composite receipts, linear in the length of the execution,
    // and supports compression via recursion.
    #[cfg(feature = "composite_prover")]
    let prover_opts = ProverOpts::composite();

    // generates Groth16 receipts which are constant size in the length of the
    // execution and small enough to verify on blockchains, like Ethereum. Only
    // supported for x86_64 Linux with Docker installed.
    #[cfg(feature = "groth16_prover")]
    let prover_opts = ProverOpts::groth16();

    default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), proving_key, &prover_opts)
        .unwrap()
        .receipt
}
