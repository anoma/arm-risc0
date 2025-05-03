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
use risc0_zkvm::sha::{rust_crypto::Sha256 as Sha256Type, Digest, Impl, Sha256, DIGEST_BYTES};

/// A resource that can be created and consumed
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
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
    pub nonce: [u8; DEFAULT_BYTES],
    // commitment to nullifier key
    pub nk_commitment: NullifierKeyCommitment,
    // randomness seed used to derive whatever randomness needed
    pub rand_seed: [u8; DEFAULT_BYTES],
}

impl Resource {
    pub fn create(
        logic_ref: Digest,
        label_ref: Digest,
        quantity: u128,
        value_ref: Digest,
        is_ephemeral: bool,
        nk_commitment: NullifierKeyCommitment,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            logic_ref,
            label_ref,
            quantity,
            value_ref,
            is_ephemeral,
            nonce: rng.gen(),
            nk_commitment,
            rand_seed: rng.gen(),
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

    fn psi(&self) -> Digest {
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
        *Impl::hash_bytes(&bytes)
    }

    fn rcm(&self) -> Digest {
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
        *Impl::hash_bytes(&bytes)
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
        *Impl::hash_bytes(&bytes)
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: &NullifierKey) -> Option<Digest> {
        let cm = self.commitment();
        self.nullifier_from_commitment(nf_key, &cm)
    }

    pub fn nullifier_from_commitment(&self, nf_key: &NullifierKey, cm: &Digest) -> Option<Digest> {
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

            Some(*Impl::hash_bytes(&bytes))
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
}
