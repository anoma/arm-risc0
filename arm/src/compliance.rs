use crate::{
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, words_to_bytes},
};
use hex::FromHex;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
#[cfg(feature = "nif")]
use rustler::NifStruct;
lazy_static! {
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.ComplianceInstance")]
pub struct ComplianceInstance {
    pub consumed_nullifier: Vec<u32>,
    pub consumed_logic_ref: Vec<u32>,
    pub consumed_commitment_tree_root: Vec<u32>,
    pub created_commitment: Vec<u32>,
    pub created_logic_ref: Vec<u32>,
    pub delta_x: Vec<u32>,
    pub delta_y: Vec<u32>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.ComplianceWitness")]
pub struct ComplianceWitness {
    /// The consumed resource
    pub consumed_resource: Resource,
    /// The path from the consumed commitment to the root in the commitment tree
    pub merkle_path: MerklePath,
    /// The existing root for the ephemeral resource
    pub ephemeral_root: Vec<u32>,
    /// Nullifier key of the consumed resource
    pub nf_key: NullifierKey,
    /// The created resource
    pub created_resource: Resource,
    /// Random scalar for delta commitment
    pub rcv: Vec<u8>,
    // TODO: If we want to add function privacy, include:
    // pub input_resource_logic_cm_r: [u8; DATA_BYTES],
    // pub output_resource_logic_cm_r: [u8; DATA_BYTES],
}

impl ComplianceWitness {
    pub fn from_resources(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        let mut rng = rand::thread_rng();
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::default(),
            rcv: Scalar::random(&mut rng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: INITIAL_ROOT.as_words().to_vec(),
        }
    }

    pub fn from_resources_with_path(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        merkle_path: MerklePath,
        created_resource: Resource,
    ) -> Self {
        let mut rng = rand::thread_rng();
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path,
            rcv: Scalar::random(&mut rng).to_bytes().to_vec(),
            nf_key,
            ephemeral_root: INITIAL_ROOT.as_words().to_vec(),
        }
    }

    // Only for tests
    pub fn with_fixed_rcv(
        consumed_resource: Resource,
        nf_key: NullifierKey,
        created_resource: Resource,
    ) -> Self {
        ComplianceWitness {
            consumed_resource,
            created_resource,
            merkle_path: MerklePath::default(),
            rcv: Scalar::ONE.to_bytes().to_vec(),
            nf_key,
            ephemeral_root: INITIAL_ROOT.as_words().to_vec(),
        }
    }

    pub fn constrain(&self) -> ComplianceInstance {
        let consumed_cm = self.consumed_commitment();
        let consumed_logic_ref = self.consumed_resource_logic();
        let consumed_commitment_tree_root = self.consumed_commitment_tree_root(&consumed_cm);

        let consumed_nullifier = self.consumed_nullifier(&consumed_cm);
        let created_logic_ref = self.created_resource_logic();
        let created_commitment = self.created_commitment();

        // constrain created_resource.nonce and consumed_resource.nf
        assert_eq!(
            self.created_resource.nonce,
            consumed_nullifier.as_bytes(),
            "Created resource nonce must match consumed nullifier"
        );

        let (delta_x, delta_y) = self.delta();

        ComplianceInstance {
            consumed_nullifier: consumed_nullifier.as_words().to_vec(),
            consumed_logic_ref: consumed_logic_ref.as_words().to_vec(),
            consumed_commitment_tree_root,
            created_commitment: created_commitment.as_words().to_vec(),
            created_logic_ref: created_logic_ref.as_words().to_vec(),
            delta_x,
            delta_y,
        }
    }

    pub fn consumed_resource_logic(&self) -> Digest {
        Digest::from_bytes(self.consumed_resource.logic_ref.clone().try_into().unwrap())
    }

    pub fn created_resource_logic(&self) -> Digest {
        Digest::from_bytes(self.created_resource.logic_ref.clone().try_into().unwrap())
    }

    pub fn consumed_commitment(&self) -> Digest {
        self.consumed_resource.commitment()
    }

    pub fn created_commitment(&self) -> Digest {
        self.created_resource.commitment()
    }

    pub fn consumed_nullifier(&self, cm: &Digest) -> Digest {
        self.consumed_resource
            .nullifier_from_commitment(&self.nf_key, cm)
            .unwrap()
    }

    pub fn consumed_commitment_tree_root(&self, cm: &Digest) -> Vec<u32> {
        if self.consumed_resource.is_ephemeral {
            self.ephemeral_root.clone()
        } else {
            self.merkle_path.root(cm)
        }
    }

    pub fn delta(&self) -> (Vec<u32>, Vec<u32>) {
        // Compute delta and make delta commitment public
        let rcv_array: [u8; 32] = self
            .rcv
            .as_slice()
            .try_into()
            .expect("rcv must be 32 bytes");
        let rcv_scalar = Scalar::from_repr(rcv_array.into()).expect("rcv must be a valid scalar");
        let delta = self.consumed_resource.kind() * self.consumed_resource.quantity_scalar()
            - self.created_resource.kind() * self.created_resource.quantity_scalar()
            + ProjectivePoint::GENERATOR * rcv_scalar;

        let encoded_delta = delta.to_encoded_point(false);

        (
            bytes_to_words(encoded_delta.x().unwrap()),
            bytes_to_words(encoded_delta.y().unwrap()),
        )
    }
}

impl Default for ComplianceWitness {
    fn default() -> Self {
        let nf_key = NullifierKey::default();

        let consumed_resource = Resource {
            logic_ref: vec![0; 32],
            label_ref: vec![0; 32],
            quantity: 1u128,
            value_ref: vec![0; 32],
            is_ephemeral: false,
            nonce: vec![0; 32],
            nk_commitment: nf_key.commit(),
            rand_seed: vec![0; 32],
        };

        let nf = consumed_resource.nullifier(&nf_key).unwrap();

        let created_resource = Resource {
            logic_ref: vec![0; 32],
            label_ref: vec![0; 32],
            quantity: 1u128,
            value_ref: vec![0; 32],
            is_ephemeral: false,
            nonce: nf.as_bytes().to_vec(),
            nk_commitment: nf_key.commit(),
            rand_seed: vec![0; 32],
        };

        let merkle_path = MerklePath::default();

        let rcv = Scalar::ONE.to_bytes().to_vec();

        ComplianceWitness {
            consumed_resource,
            created_resource,
            ephemeral_root: INITIAL_ROOT.as_words().to_vec(),
            merkle_path,
            rcv,
            nf_key,
        }
    }
}

impl ComplianceInstance {
    pub fn delta_projective(&self) -> ProjectivePoint {
        let x: [u8; 32] = words_to_bytes(&self.delta_x)
            .try_into()
            .expect("delta_x must be 32 bytes");
        let y: [u8; 32] = words_to_bytes(&self.delta_y)
            .try_into()
            .expect("delta_y must be 32 bytes");
        let encoded_point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        ProjectivePoint::from_encoded_point(&encoded_point).unwrap()
    }

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(words_to_bytes(&self.consumed_nullifier));
        msg.extend_from_slice(words_to_bytes(&self.created_commitment));
        msg
    }
}
