use risc0_zkvm::{
    default_prover,
    sha::{Digest, DIGEST_BYTES},
    ExecutorEnv, ProverOpts, Receipt, VerifierContext,
};
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
pub fn verify(receipt: &Receipt, verifying_key: &[u8]) -> bool {
    let verifying_key = if verifying_key.len() == DIGEST_BYTES {
        Digest::from_bytes(verifying_key.try_into().unwrap())
    } else {
        return false;
    };
    receipt.verify(verifying_key).is_ok()
}
