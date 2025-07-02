use risc0_zkvm::{
    default_prover,
    sha::{Digest, DIGEST_BYTES},
    ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde::{de::DeserializeOwned, Serialize};

// It takes a proving key and a witness, and returns the proof and the instance
pub fn prove<T: Serialize>(proving_key: &[u8], witness: &T) -> (Vec<u8>, Vec<u8>) {
    // TODO: add other proving options(STARK, COMPOSITION)
    let receipt = groth16_prove(witness, proving_key);

    let proof = bincode::serialize(&receipt.inner).unwrap();
    let instance = receipt.journal.bytes;
    (proof, instance)
}

// Receipt contains the proof and the public inputs
pub fn verify(verifying_key: &[u8], instance: &[u8], proof: &[u8]) -> bool {
    let verifying_key = if verifying_key.len() == DIGEST_BYTES {
        Digest::from_bytes(verifying_key.try_into().unwrap())
    } else {
        return false;
    };

    let inner: InnerReceipt = bincode::deserialize(proof).unwrap();
    let receipt = Receipt::new(inner, instance.to_vec());

    receipt.verify(verifying_key).is_ok()
}

pub fn journal_to_instance<T: DeserializeOwned>(journal: &[u8]) -> T {
    let journal = risc0_zkvm::Journal {
        bytes: journal.to_vec(),
    };
    journal.decode().unwrap()
}

pub fn convert_image_id_to_bytes(id: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(id.len() * 4);
    for &word in id {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

// TODO: handle errors properly
fn groth16_prove<T: Serialize>(witness: &T, proving_key: &[u8]) -> Receipt {
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
