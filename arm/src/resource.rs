const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
const PRF_EXPAND_PERSONALIZATION_LEN: usize = 16;
const PRF_EXPAND_PERSONALIZATION: &[u8; PRF_EXPAND_PERSONALIZATION_LEN] = b"RISC0_ExpandSeed";
const PRF_EXPAND_PSI: u8 = 0;
const PRF_EXPAND_RCM: u8 = 1;
const QUANTITY_BYTES: usize = 16;
const RESOURCE_BYTES: usize = DIGEST_BYTES
    + DIGEST_BYTES
    + DIGEST_BYTES
    + QUANTITY_BYTES
    + 1
    + DIGEST_BYTES
    + DIGEST_BYTES
    + DIGEST_BYTES;

use crate::{
    error::ArmError,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
};

use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    ProjectivePoint, Scalar, Secp256k1,
};
use rand::Rng;
use risc0_zkvm::sha::{rust_crypto::Sha256 as Sha256Type, Impl, Sha256, DIGEST_BYTES};
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// A resource that can be created and consumed
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Resource {
    // a succinct representation of the predicate associated with the resource
    pub logic_ref: Digest,
    // specifies the fungibility domain for the resource
    pub label_ref: Digest,
    // number representing the quantity of the resource
    pub quantity: u128,
    // the fungible value reference of the resource
    pub value_ref: Digest,
    // flag that reflects the resource ephemerality
    pub is_ephemeral: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: [u8; DIGEST_BYTES],
    // commitment to nullifier key
    pub nk_commitment: NullifierKeyCommitment,
    // randomness seed used to derive whatever randomness needed
    pub rand_seed: [u8; DIGEST_BYTES],
}

impl Resource {
    pub fn create(
        logic_ref: Digest,
        label_ref: Digest,
        quantity: u128,
        value_ref: Digest,
        is_ephemeral: bool,
        nonce: Digest,
        nk_commitment: NullifierKeyCommitment,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            logic_ref,
            label_ref,
            quantity,
            value_ref,
            is_ephemeral,
            nonce: nonce
                .as_bytes()
                .try_into()
                .expect("it can not fail since the digest length is always 32 bytes"),
            nk_commitment,
            rand_seed: rng.gen(),
        }
    }

    // Convert the quantity to a field element
    pub fn quantity_scalar(&self) -> Scalar {
        Scalar::from(self.quantity)
    }

    // Compute the kind of the resource
    pub fn kind(&self) -> Result<ProjectivePoint, ArmError> {
        // Concatenate the logic_ref and label_ref
        let mut bytes = [0u8; DIGEST_BYTES * 2];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.logic_ref.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES * 2].clone_from_slice(self.label_ref.as_ref());
        // Hash to a curve point
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST])
            .map_err(|_| ArmError::InvalidResourceKind)
    }

    fn psi(&self) -> Vec<u8> {
        let mut bytes = [0u8; PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        bytes[offset..offset + 16].clone_from_slice(PRF_EXPAND_PERSONALIZATION);
        offset += PRF_EXPAND_PERSONALIZATION_LEN;
        // Write the PRF_EXPAND_PSI
        bytes[offset..offset + 1].clone_from_slice(&PRF_EXPAND_PSI.to_be_bytes());
        offset += 1;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.rand_seed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(
            offset,
            PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES
        );
        Impl::hash_bytes(&bytes).as_bytes().to_vec()
    }

    fn rcm(&self) -> Vec<u8> {
        let mut bytes = [0u8; PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the PRF_EXPAND_PERSONALIZATION
        bytes[offset..offset + 16].clone_from_slice(PRF_EXPAND_PERSONALIZATION);
        offset += PRF_EXPAND_PERSONALIZATION_LEN;
        // Write the PRF_EXPAND_RCM
        bytes[offset..offset + 1].clone_from_slice(&PRF_EXPAND_RCM.to_be_bytes());
        offset += 1;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.rand_seed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(
            offset,
            PRF_EXPAND_PERSONALIZATION_LEN + 1 + 2 * DIGEST_BYTES
        );
        Impl::hash_bytes(&bytes).as_bytes().to_vec()
    }

    // Compute the commitment to the resource
    pub fn commitment(&self) -> Digest {
        // Concatenate all the components of this resource
        let mut bytes = [0u8; RESOURCE_BYTES];
        let mut offset: usize = 0;
        // Write the image ID bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.logic_ref.as_ref());
        offset += DIGEST_BYTES;
        // Write the label_ref bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.label_ref.as_ref());
        offset += DIGEST_BYTES;
        // Write the quantity bytes
        bytes[offset..offset + QUANTITY_BYTES]
            .clone_from_slice(self.quantity.to_be_bytes().as_ref());
        offset += QUANTITY_BYTES;
        // Write the fungible value_ref bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.value_ref.as_ref());
        offset += DIGEST_BYTES;
        // Write the ephemeral flag
        bytes[offset..offset + 1].clone_from_slice(&[self.is_ephemeral as u8]);
        offset += 1;
        // Write the nonce bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
        offset += DIGEST_BYTES;
        // Write the nullifier public key bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nk_commitment.inner().as_ref());
        offset += DIGEST_BYTES;
        // Write the randomness seed bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.rcm().as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, RESOURCE_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: &NullifierKey) -> Result<Digest, ArmError> {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, &cm)
    }

    pub fn nullifier_from_commitment(
        &self,
        nf_key: &NullifierKey,
        cm: &Digest,
    ) -> Result<Digest, ArmError> {
        // Make sure that the nullifier public key corresponds to the secret key
        if self.nk_commitment == nf_key.commit() {
            let mut bytes = [0u8; 4 * DIGEST_BYTES];
            let mut offset: usize = 0;
            // Write the nullifier secret key
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(nf_key.inner().as_ref());
            offset += DIGEST_BYTES;
            // Write the nonce
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
            offset += DIGEST_BYTES;
            // Write psi
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.psi().as_ref());
            offset += DIGEST_BYTES;
            // Write the resource commitment
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(cm.as_bytes());
            offset += DIGEST_BYTES;

            assert_eq!(offset, 4 * DIGEST_BYTES);

            Ok(*Impl::hash_bytes(&bytes))
        } else {
            Err(ArmError::InvalidNullifierKey)
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ArmError> {
        bincode::serialize(self).map_err(|_| ArmError::InvalidResourceSerialization)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArmError> {
        bincode::deserialize(bytes).map_err(|_| ArmError::InvalidResourceDeserialization)
    }

    pub fn set_value_ref(&mut self, value_ref: Digest) {
        self.value_ref = value_ref;
    }

    pub fn set_nf_commitment(&mut self, nf_commitment: NullifierKeyCommitment) {
        self.nk_commitment = nf_commitment;
    }

    pub fn reset_randomness(&mut self) {
        let mut rng = rand::thread_rng();
        self.rand_seed = rng.gen();
    }

    pub fn set_nonce(&mut self, nf: Digest) {
        self.nonce = nf
            .as_bytes()
            .try_into()
            .expect("it can not fail since the digest length is always 32 bytes");
    }

    pub fn set_nonce_from_nf(
        &mut self,
        resource: &Resource,
        nf_key: &NullifierKey,
    ) -> Result<(), ArmError> {
        self.nonce = resource
            .nullifier(nf_key)?
            .as_bytes()
            .try_into()
            .map_err(|_| ArmError::InvalidResourceNonce)?;
        Ok(())
    }

    pub fn tag(&self, is_consumed: bool, nf_key: &NullifierKey) -> Result<Digest, ArmError> {
        let cm = self.commitment();
        if is_consumed {
            self.nullifier_from_commitment(nf_key, &cm)
        } else {
            Ok(cm)
        }
    }
}

impl Default for Resource {
    fn default() -> Self {
        Self {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 0,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce: [0; DIGEST_BYTES],
            nk_commitment: NullifierKeyCommitment::default(),
            rand_seed: [0; DIGEST_BYTES],
        }
    }
}
