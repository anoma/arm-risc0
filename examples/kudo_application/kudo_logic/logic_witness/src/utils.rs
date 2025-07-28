use arm_core::authorization::{
    AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey,
};
use risc0_zkvm::sha::{Impl, Sha256};

pub fn compute_kudo_label(
    denomination_logic: &[u8],
    issuer: &AuthorizationVerifyingKey,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(denomination_logic);
    bytes.extend_from_slice(&issuer.to_bytes());
    Impl::hash_bytes(&bytes).as_bytes().to_vec()
}

pub fn compute_kudo_value(owner: &AuthorizationVerifyingKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&owner.to_bytes());
    Impl::hash_bytes(&bytes).as_bytes().to_vec()
}

pub fn generate_receive_signature(
    receive_logic: &[u8],
    sk: &AuthorizationSigningKey,
) -> AuthorizationSignature {
    let pk = AuthorizationVerifyingKey::from_signing_key(sk);
    let mut msg = Vec::new();
    msg.extend_from_slice(receive_logic);
    msg.extend_from_slice(&pk.to_bytes());
    sk.sign(&msg)
}
