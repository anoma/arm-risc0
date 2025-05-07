use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use serde::Serialize;

// TODO: handle errors properly
pub fn groth16_prove<T: Serialize>(witness: &T, elf: &[u8]) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();

    default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            elf,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}
