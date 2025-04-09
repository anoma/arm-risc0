use aarm_core::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::Ciphertext,
};
use k256::{AffinePoint, Scalar};
use risc0_zkvm::guest::env;

// Guest code:
// This is the portion of the code that will be proven
pub fn main() {
    let (msg, receiver_pk, sender_sk, nonce, sig_vk, sig_msg, signature): (
        Vec<u8>,
        AffinePoint,
        Scalar,
        [u8; 12],
        AuthorizationVerifyingKey,
        Vec<u8>,
        AuthorizationSignature,
    ) = env::read();
    let ciphertext = Ciphertext::encrypt(&msg, &receiver_pk, &sender_sk, nonce);

    let ret_sig = sig_vk.verify(&sig_msg, &signature).is_ok();
    env::commit(&(ciphertext, ret_sig));
}
