use aarm_core::encryption::Ciphertext;
use k256::{Scalar, AffinePoint};
use risc0_zkvm::guest::env;

// Guest code:
// This is the portion of the code that will be proven
pub fn main() {
    let (msg, receiver_pk, sender_sk, nonce): (Vec<u8>, AffinePoint, Scalar, [u8; 12]) = env::read();
    let ciphertext = Ciphertext::encrypt(&msg, &receiver_pk, &sender_sk, nonce);
    env::commit(&ciphertext);
}
