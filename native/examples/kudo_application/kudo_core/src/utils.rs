use aarm_core::authorization::{
    AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey,
};
use risc0_zkvm::sha::{Digest, Impl, Sha256};

pub fn compute_kudo_label(
    denomination_logic: &Digest,
    issuer: &AuthorizationVerifyingKey,
) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(denomination_logic.as_bytes());
    bytes.extend_from_slice(&issuer.to_bytes());
    *Impl::hash_bytes(&bytes)
}

pub fn compute_kudo_value(owner: &AuthorizationVerifyingKey) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&owner.to_bytes());
    *Impl::hash_bytes(&bytes)
}

pub fn generate_receive_signature(
    receive_logic: &Digest,
    sk: &AuthorizationSigningKey,
) -> AuthorizationSignature {
    let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
    let mut msg = Vec::new();
    msg.extend_from_slice(receive_logic.as_bytes());
    msg.extend_from_slice(&pk.to_bytes());
    sk.sign(&msg)
}
