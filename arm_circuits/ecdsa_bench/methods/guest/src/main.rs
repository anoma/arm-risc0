use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn main() {
    // Vec<u8> is used for vk (33 bytes) and sigs (64 bytes) because risc0's
    // serde_core only implements Deserialize for fixed arrays up to size 32.
    let vk_bytes: Vec<u8> = env::read();
    let items: Vec<(Vec<u8>, [u8; 32])> = env::read();

    let vk = VerifyingKey::from_sec1_bytes(&vk_bytes).unwrap();

    for (sig_bytes, msg) in &items {
        let sig = Signature::from_slice(sig_bytes).unwrap();
        // Use the RISC Zero SHA-256 accelerator for prehashing
        let prehash = Impl::hash_bytes(msg);
        vk.verify_prehash(prehash.as_bytes(), &sig).unwrap();
    }

    env::commit(&(items.len() as u32));
}
