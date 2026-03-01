use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn main() {
    let count: u32 = env::read();

    // Start with a fixed 32-byte input and chain hashes
    let mut data = [0u8; 32];
    for _ in 0..count {
        let digest = Impl::hash_bytes(&data);
        data.copy_from_slice(digest.as_bytes());
    }

    env::commit(&data);
}
