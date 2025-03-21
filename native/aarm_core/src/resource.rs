use k256::{
    elliptic_curve::{
        group::ff::PrimeField,
        hash2curve::{ExpandMsgXmd, GroupDigest},
    },
    ProjectivePoint, Scalar, Secp256k1,
};
use risc0_zkvm::sha::{rust_crypto::Sha256 as Sha256Type, Digest, Impl, Sha256, DIGEST_BYTES};

use crate::constants::{DEFAULT_BYTES, DST, RESOURCE_BYTES};
use crate::nullifier::{NullifierKey, NullifierKeyCommitment};

/// A resource that can be created and consumed
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Resource {
    // a succinct representation of the predicate associated with the resource
    pub logic_ref: Digest,
    // specifies the fungibility domain for the resource
    pub label_ref: [u8; DEFAULT_BYTES],
    // number representing the quantity of the resource
    pub quantity: [u8; DEFAULT_BYTES],
    // the fungible value reference of the resource
    pub value_ref: [u8; DEFAULT_BYTES],
    // flag that reflects the resource ephemerality
    pub is_ephemeral: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: Digest,
    // commitment to nullifier key
    pub nk_commitment: NullifierKeyCommitment,
    // randomness seed used to derive whatever randomness needed
    pub rand_seed: [u8; DEFAULT_BYTES],
}

impl Resource {
    // Number representing the quantity of the resource
    pub fn quantity(&self) -> Scalar {
        // Convert to a field element
        Scalar::from_repr(self.quantity.into()).unwrap()
    }

    // The kind is a function of the label_ref and image ID. Must be infeasible to map different pairs to the same kind.
    pub fn kind(&self) -> ProjectivePoint {
        // Concatenate the image ID and label_ref
        let mut bytes = [0u8; DIGEST_BYTES + 32];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.logic_ref.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES + 32].clone_from_slice(&self.label_ref);
        // Hash to a curve point
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST]).unwrap()
    }

    fn psi(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.rand_seed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        *Impl::hash_bytes(&bytes)
    }

    pub fn rcm(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 1;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.rand_seed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
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
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.label_ref);
        offset += DEFAULT_BYTES;
        // Write the quantity bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.quantity);
        offset += DEFAULT_BYTES;
        // Write the fungible value_ref bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.value_ref);
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
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.rand_seed);
        offset += DEFAULT_BYTES;
        assert_eq!(offset, RESOURCE_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nf_key: NullifierKey) -> Option<Digest> {
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
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.commitment().as_ref());
            offset += DIGEST_BYTES;

            assert_eq!(offset, 4 * DIGEST_BYTES);

            Some(*Impl::hash_bytes(&bytes))
        } else {
            None
        }
    }
}
