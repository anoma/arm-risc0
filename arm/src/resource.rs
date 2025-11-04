const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
const PRF_EXPAND_PERSONALIZATION_LEN: usize = 16;
const PRF_EXPAND_PERSONALIZATION: &[u8; PRF_EXPAND_PERSONALIZATION_LEN] = b"RISC0_ExpandSeed";
const PRF_EXPAND_PSI: u8 = 0;
const PRF_EXPAND_RCM: u8 = 1;
const DEFAULT_BYTES: usize = 32;
const QUANTITY_BYTES: usize = 16;
const RESOURCE_BYTES: usize = DIGEST_BYTES
    + DEFAULT_BYTES
    + DEFAULT_BYTES
    + QUANTITY_BYTES
    + 1
    + DIGEST_BYTES
    + DIGEST_BYTES
    + DEFAULT_BYTES;

use crate::{
    error::ArmError,
    merkle_path::MerklePath,
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
    pub nonce: [u8; 32],
    // commitment to nullifier key
    pub nk_commitment: NullifierKeyCommitment,
    // randomness seed used to derive whatever randomness needed
    pub rand_seed: [u8; 32],
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

    /// Derives the nonce based on the passed index and nullifiers.
    /// The index must fit in a 32-bit integer.
    pub fn derive_nonce_from_nullifiers(
        index: usize,
        nullifiers: &[Digest],
    ) -> Result<[u8; 32], ArmError> {
        let nullifiers_digest = Self::hash_nullifiers(nullifiers);

        Self::derive_nonce(index, nullifiers_digest)
    }

    /// Derives the nonce based on the passed index and digest.
    /// The index must fit in a 32-bit integer.
    pub fn derive_nonce(index: usize, nullifiers_digest: Digest) -> Result<[u8; 32], ArmError> {
        let index_u32: u32 = index
            .try_into()
            .map_err(|_| ArmError::InvalidResourceIndex)?;
        let mut bytes = [0u8; DIGEST_BYTES + 4];
        bytes[0..4].clone_from_slice(&index_u32.to_le_bytes());
        bytes[4..DIGEST_BYTES + 4].clone_from_slice(nullifiers_digest.as_ref());

        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .map_err(|_| ArmError::InvalidResourceNonce)
    }

    pub fn hash_nullifiers(nullifiers: &[Digest]) -> Digest {
        let mut bytes = Vec::new();
        for nf in nullifiers.iter() {
            bytes.append(&mut nf.as_bytes().to_vec().clone());
        }

        Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap()
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
            nonce: [0; 32],
            nk_commitment: NullifierKeyCommitment::default(),
            rand_seed: [0; 32],
        }
    }
}

/// Private information related to a consumed resource
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsumedDatum {
    /// The consumed resource.
    pub resource: Resource,
    /// The path from the consumed commitment to the root of the commitment tree
    pub merkle_path: MerklePath,
    /// Nullifier key of the consumed resource
    pub nf_key: NullifierKey,
}

impl ConsumedDatum {
    /// Datum constructor for an ephemeral resource.
    pub fn from_resource(resource: Resource, nf_key: NullifierKey) -> ConsumedDatum {
        ConsumedDatum {
            resource,
            merkle_path: MerklePath::empty(),
            nf_key: nf_key.clone(),
        }
    }

    /// Datum constructor for a persistent resource.
    pub fn from_resource_with_path(
        resource: Resource,
        nf_key: NullifierKey,
        merkle_path: MerklePath,
    ) -> ConsumedDatum {
        ConsumedDatum {
            resource,
            merkle_path,
            nf_key: nf_key.clone(),
        }
    }
}

impl Default for ConsumedDatum {
    /// The default value is meaningless and only for testing
    fn default() -> Self {
        let nf_key = NullifierKey::default();

        let resource = Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: [0u8; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: [0u8; 32],
        };

        let merkle_path = MerklePath::default();

        Self {
            resource,
            merkle_path,
            nf_key,
        }
    }
}

/// Public information of consumed resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsumedMemorandum {
    /// The nullifier of the consumed [Resource]
    pub resource_nullifier: Digest,
    /// The logic reference of the consumed [Resource]
    pub resource_logic_ref: Digest,
    /// The root of the Merkle tree where the resource commitment is in.
    pub commitment_tree_root: Digest,
}

/// Public information of created resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CreatedMemorandum {
    /// The commitment to the created [Resource]
    pub resource_commitment: Digest,
    /// The logic reference of the created [Resource].
    pub resource_logic_ref: Digest,
}
