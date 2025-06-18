use std::vec;

use crate::constants::{
    DEFAULT_BYTES, DST, PRF_EXPAND_PERSONALIZATION, PRF_EXPAND_PERSONALIZATION_LEN, PRF_EXPAND_PSI,
    PRF_EXPAND_RCM, QUANTITY_BYTES, RESOURCE_BYTES,
};
use crate::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    ProjectivePoint, Scalar, Secp256k1,
};
use rand::Rng;
use risc0_zkvm::sha::{rust_crypto::Sha256 as Sha256Type, Impl, Sha256, DIGEST_BYTES};
#[cfg(feature = "nif")]
use rustler::NifStruct;
use serde::{Deserialize, Serialize};

/// A resource that can be created and consumed
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.Resource")]
pub struct Resource {
    // a succinct representation of the predicate associated with the resource
    pub logic_ref: Vec<u8>,
    // specifies the fungibility domain for the resource
    pub label_ref: Vec<u8>,
    // number representing the quantity of the resource
    pub quantity: u128,
    // the fungible value reference of the resource
    pub value_ref: Vec<u8>,
    // flag that reflects the resource ephemerality
    pub is_ephemeral: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: Vec<u8>,
    // commitment to nullifier key
    pub nk_commitment: NullifierKeyCommitment,
    // randomness seed used to derive whatever randomness needed
    pub rand_seed: Vec<u8>,
}

impl Resource {
    pub fn create(
        logic_ref: Vec<u8>,
        label_ref: Vec<u8>,
        quantity: u128,
        value_ref: Vec<u8>,
        is_ephemeral: bool,
        nk_commitment: NullifierKeyCommitment,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let nonce: [u8; DEFAULT_BYTES] = rng.gen();
        let rand_seed: [u8; DEFAULT_BYTES] = rng.gen();
        Self {
            logic_ref,
            label_ref,
            quantity,
            value_ref,
            is_ephemeral,
            nonce: nonce.to_vec(),
            nk_commitment,
            rand_seed: rand_seed.to_vec(),
        }
    }

    // Convert the quantity to a field element
    pub fn quantity_scalar(&self) -> Scalar {
        Scalar::from(self.quantity)
    }

    // Compute the kind of the resource
    pub fn kind(&self) -> ProjectivePoint {
        // Concatenate the logic_ref and label_ref
        let mut bytes = [0u8; DIGEST_BYTES * 2];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.logic_ref.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES * 2].clone_from_slice(self.label_ref.as_ref());
        // Hash to a curve point
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST]).unwrap()
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
    pub fn commitment(&self) -> Vec<u8> {
        // Concatenate all the components of this resource
        let mut bytes = [0u8; RESOURCE_BYTES];
        let mut offset: usize = 0;
        // Write the image ID bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.logic_ref.as_ref());
        offset += DIGEST_BYTES;
        // Write the label_ref bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(self.label_ref.as_ref());
        offset += DEFAULT_BYTES;
        // Write the quantity bytes
        bytes[offset..offset + QUANTITY_BYTES]
            .clone_from_slice(self.quantity.to_be_bytes().as_ref());
        offset += QUANTITY_BYTES;
        // Write the fungible value_ref bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(self.value_ref.as_ref());
        offset += DEFAULT_BYTES;
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
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(self.rcm().as_ref());
        offset += DEFAULT_BYTES;
        assert_eq!(offset, RESOURCE_BYTES);
        // Now produce the hash
        Impl::hash_bytes(&bytes).as_bytes().to_vec()
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: &NullifierKey) -> Option<Vec<u8>> {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, &cm)
    }

    pub fn nullifier_from_commitment(&self, nf_key: &NullifierKey, cm: &[u8]) -> Option<Vec<u8>> {
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
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(cm.as_ref());
            offset += DIGEST_BYTES;

            assert_eq!(offset, 4 * DIGEST_BYTES);

            Some(Impl::hash_bytes(&bytes).as_bytes().to_vec())
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn set_value_ref(&mut self, value_ref: Vec<u8>) {
        self.value_ref = value_ref;
    }

    pub fn set_nf_commitment(&mut self, nf_commitment: NullifierKeyCommitment) {
        self.nk_commitment = nf_commitment;
    }

    pub fn reset_randomness_nonce(&mut self) {
        let mut rng = rand::thread_rng();
        let nonce: [u8; DEFAULT_BYTES] = rng.gen();
        let rand_seed: [u8; DEFAULT_BYTES] = rng.gen();
        self.rand_seed = rand_seed.to_vec();
        self.nonce = nonce.to_vec();
    }
}

impl Default for Resource {
    fn default() -> Self {
        Self {
            logic_ref: vec![0; DEFAULT_BYTES],
            label_ref: vec![0; DEFAULT_BYTES],
            quantity: 0,
            value_ref: vec![0; DEFAULT_BYTES],
            is_ephemeral: true,
            nonce: vec![0; DEFAULT_BYTES],
            nk_commitment: NullifierKeyCommitment::default(),
            rand_seed: vec![0; DEFAULT_BYTES],
        }
    }
}
