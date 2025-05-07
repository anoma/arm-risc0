use aarm_core::authorization::AuthorizationVerifyingKey;
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
