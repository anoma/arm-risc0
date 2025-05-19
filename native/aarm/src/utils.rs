use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use serde::Serialize;

// TODO: handle errors properly
pub fn groth16_prove<T: Serialize>(witness: &T, proving_key: &[u8]) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();

    default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            proving_key,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}

// TODO: add a stark prove API

// Receipt contains the proof and the public inputs
pub fn verify(receipt: &Receipt, verifying_key: impl Into<Digest>) -> bool {
    receipt.verify(verifying_key).is_ok()
}
