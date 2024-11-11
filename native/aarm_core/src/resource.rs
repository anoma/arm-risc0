
use k256::{
    elliptic_curve::{
        group::ff::PrimeField,
        hash2curve::{ExpandMsgXmd, GroupDigest},
    },
    ProjectivePoint, Scalar, Secp256k1,
};
use risc0_zkvm::sha::{Sha256, rust_crypto::Sha256 as Sha256Type, Digest, Impl, DIGEST_BYTES};

use crate::constants::{DEFAULT_BYTES, DST, RESOURCE_BYTES};
use crate::nullifier::{Npk, Nsk};

/// A resource that can be created and consumed
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Resource {
    // a succinct representation of the predicate associated with the resource
    pub logic: Digest,
    // specifies the fungibility domain for the resource
    pub label: [u8; DEFAULT_BYTES],
    // number representing the quantity of the resource
    pub quantity: [u8; DEFAULT_BYTES],
    // the fungible data of the resource
    pub data: [u8; DEFAULT_BYTES],
    // flag that reflects the resource ephemerality
    pub eph: bool,
    // guarantees the uniqueness of the resource computable components
    pub nonce: Digest,
    // nullifier public key
    pub npk: Npk,
    // randomness seed used to derive whatever randomness needed
    pub rseed: [u8; DEFAULT_BYTES],
}

impl Resource {
    // Number representing the quantity of the resource
    pub fn quantity(&self) -> Scalar {
        // Convert to a field element
        Scalar::from_repr(self.quantity.into()).unwrap()
    }

    // The kind is a function of the label and image ID. Must be infeasible to map different pairs to the same kind.
    pub fn kind(&self) -> ProjectivePoint {
        // Concatenate the image ID and label
        let mut bytes = [0u8; DIGEST_BYTES + 32];
        bytes[0..DIGEST_BYTES].clone_from_slice(self.logic.as_ref());
        bytes[DIGEST_BYTES..DIGEST_BYTES + 32].clone_from_slice(&self.label);
        // Hash to a curve point
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256Type>>(&[&bytes], &[DST]).unwrap()
    }

    pub fn psi(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 0;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.rseed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
        offset += DIGEST_BYTES;
        assert_eq!(offset, 2 * DIGEST_BYTES);
        *Impl::hash_bytes(&bytes)
    }

    pub fn rcm(&self) -> Digest {
        let mut bytes = [0u8; 2 * DIGEST_BYTES];
        let mut offset: usize = 1;
        // Write the random seed
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.rseed.as_ref());
        offset += DIGEST_BYTES;
        // Write the nonce
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
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
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.logic.as_ref());
        offset += DIGEST_BYTES;
        // Write the label bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.label);
        offset += DEFAULT_BYTES;
        // Write the quantity bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.quantity);
        offset += DEFAULT_BYTES;
        // Write the fungible data bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.data);
        offset += DEFAULT_BYTES;
        // Write the ephemeral flag
        bytes[offset..offset + 1].clone_from_slice(&[self.eph as u8]);
        offset += 1;
        // Write the nonce bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
        offset += DIGEST_BYTES;
        // Write the nullifier public key bytes
        bytes[offset..offset + DIGEST_BYTES].clone_from_slice(self.npk.inner().as_ref());
        offset += DIGEST_BYTES;
        // Write the randomness seed bytes
        bytes[offset..offset + DEFAULT_BYTES].clone_from_slice(&self.rseed);
        offset += DEFAULT_BYTES;
        assert_eq!(offset, RESOURCE_BYTES);
        // Now produce the hash
        *Impl::hash_bytes(&bytes)
    }

    // Compute the nullifier of the resource
    pub fn nullifier(&self, nsk: Nsk) -> Option<Digest> {
        // Make sure that the nullifier public key corresponds to the secret key
        if self.npk == nsk.public_key() {
            let mut bytes = [0u8; 4 * DIGEST_BYTES];
            let mut offset: usize = 0;
            // Write the nullifier secret key
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&nsk.inner().as_ref());
            offset += DIGEST_BYTES;
            // Write the nonce
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.nonce.as_ref());
            offset += DIGEST_BYTES;
            // Write psi
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.psi().as_ref());
            offset += DIGEST_BYTES;
            // Write the resource commitment
            bytes[offset..offset + DIGEST_BYTES].clone_from_slice(&self.commitment().as_ref());
            offset += DIGEST_BYTES;

            assert_eq!(offset, 4 * DIGEST_BYTES);

            Some(*Impl::hash_bytes(&bytes))
        } else {
            None
        }
    }
}
