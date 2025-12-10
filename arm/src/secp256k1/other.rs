use k256::ecdsa::{SigningKey};
use k256::{
    elliptic_curve::{scalar::IsHigh, PublicKey, ScalarPrimitive},
    ProjectivePoint, Scalar, SecretKey,
};

use super::EthRecoveryId;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Signature(k256::ecdsa::Signature);

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct VerifyingKey(k256::ecdsa::VerifyingKey);

impl VerifyingKey {
    pub fn recover(
        &self,
        prehashed: &[u8; 32],
        recid: EthRecoveryId,
        signature: &Signature,
    ) -> Option<VerifyingKey> {
        Some(VerifyingKey(
            k256::ecdsa::VerifyingKey::recover_from_prehash(
                &prehashed[..],
                &signature.0,
                recid.into(),
            )
            .ok()?,
        ))
    }
}
