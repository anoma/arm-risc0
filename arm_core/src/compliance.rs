//! Compliance module containing the compliance instance and witness.

use crate::merkle_path::{MerklePath, PADDING_LEAF};
#[cfg(test)]
use crate::nullifier_key::NullifierKey;
use crate::resource::{ComplianceResourceInstance, ResourceWitness};
#[cfg(test)]
use crate::resource::{Resource, ResourceWitnessConsumed};
use risc0_zkp::core::digest::Digest;

/// The root of the empty commitment tree: [`PADDING_LEAF`], sha256("EMPTY").
pub const INITIAL_ROOT: Digest = PADDING_LEAF;

/// The compliance instance contains all public inputs to the compliance proof.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComplianceInstance {
    /// The part of the instance for each consumed and created resource, in the
    /// order of the witness.
    pub resource_instances: Vec<ComplianceResourceInstance>,
    /// The delta x coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_x: [u32; 8],
    /// The delta y coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_y: [u32; 8],
    /// Merkle root of the kind tree supplied with this proof.
    pub kind_tree_root: Digest,
}

/// A leaf of the kind tree, binding (logic_ref, label_ref) to a pre-computed
/// kind base. Avoids hash-to-curve inside the circuit for known resource
/// types.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KindTreeEntry {
    /// Logic ref component of the key.
    pub logic_ref: Digest,
    /// Label ref component of the key.
    pub label_ref: Digest,
    /// Uncompressed SEC1-encoded kind base (65 bytes).
    pub kind_base: Vec<u8>,
}

/// A per-resource read-out of the kind tree: the pre-computed kind base for a
/// resource together with a Merkle path proving its leaf is in the tree.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KindPath {
    /// Uncompressed SEC1-encoded kind base (65 bytes).
    pub kind_base: Vec<u8>,
    /// Merkle path from `hash_kind_tree_leaf(logic_ref, label_ref, kind_base)` to the root.
    pub path: MerklePath,
}

/// The compliance witness contains all private inputs to the compliance proof.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComplianceWitness {
    /// The part of the witness for each consumed and created resource. Their order
    /// sets the order of the resources in the instance and of the leaves of
    /// the action tree. The nonce of a created resource derives from its index
    /// among the created resources and from the consumed nullifiers, both in
    /// this order.
    pub resource_witnesses: Vec<ResourceWitness>,
    /// The existing root for ephemeral resources
    pub ephemeral_root: Digest,
    /// Bytes of randomness for the delta commitment `rcv`
    pub rcv: Vec<u8>,
    /// Per-resource Merkle paths into the kind tree, in the order of `resource_witnesses`.
    /// `None` means no pre-computed kind base — fall back to `hash_to_curve`.
    /// The `kind_tree_root` committed in the instance is derived in-circuit:
    /// the root of the first non-`None` path, or `PADDING_LEAF` if all are `None`.
    pub kind_paths: Vec<Option<KindPath>>,
}

impl ComplianceWitness {
    /// Creates a new compliance witness from each of its component parts.
    /// The randomized constructors in the host engine
    /// (`anoma-rm-risc0`'s `compliance::from_resources*`) are convenience
    /// wrappers that draw `rcv` and delegate here.
    pub fn from_parts(
        resource_witnesses: Vec<ResourceWitness>,
        ephemeral_root: Digest,
        rcv: &[u8],
        kind_paths: Vec<Option<KindPath>>,
    ) -> ComplianceWitness {
        ComplianceWitness {
            resource_witnesses,
            ephemeral_root,
            rcv: rcv.to_vec(),
            kind_paths,
        }
    }
}

/// SHA-256 leaf hash for a kind tree entry:
/// `sha256(logic_ref || label_ref || kind_base)`.
/// This is the leaf encoding used when building the Merkle tree and when
/// verifying per-resource Merkle paths inside the compliance circuit.
pub fn hash_kind_tree_leaf(entry: &KindTreeEntry) -> Digest {
    let mut bytes = Vec::with_capacity(32 + 32 + entry.kind_base.len());
    bytes.extend_from_slice(entry.logic_ref.as_bytes());
    bytes.extend_from_slice(entry.label_ref.as_bytes());
    bytes.extend_from_slice(&entry.kind_base);
    crate::utils::hash_bytes(&bytes)
}

#[cfg(test)]
impl Default for ComplianceWitness {
    /// The default value is meaningless and only for testing.
    /// It contains three consumed and two created resources.
    fn default() -> Self {
        let consumed_data = vec![ResourceWitnessConsumed::default(); 3];

        let consumed_nullifiers: Vec<Digest> = consumed_data
            .iter()
            .map(|w| w.resource.nullifier(&w.nf_key).unwrap())
            .collect();

        let nonce_0 = Resource::derive_nonce_from_nullifiers(0, &consumed_nullifiers).unwrap();
        let nonce_1 = Resource::derive_nonce_from_nullifiers(1, &consumed_nullifiers).unwrap();

        let make_created = |nonce| Resource {
            logic_ref: Digest::default(),
            label_ref: Digest::default(),
            quantity: 1u128,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce,
            nk_commitment: NullifierKey::default().commit(),
            rand_seed: [0u8; 32],
        };

        let resource_witnesses: Vec<ResourceWitness> = consumed_data
            .into_iter()
            .map(ResourceWitness::Consumed)
            .chain([make_created(nonce_0), make_created(nonce_1)].map(ResourceWitness::Created))
            .collect();
        let n_paths = resource_witnesses.len();
        ComplianceWitness {
            resource_witnesses,
            ephemeral_root: INITIAL_ROOT,
            // Scalar 1 in big-endian repr (k256's Scalar::ONE.to_bytes()).
            rcv: {
                let mut rcv = vec![0u8; 32];
                rcv[31] = 1;
                rcv
            },
            kind_paths: (0..n_paths).map(|_| None).collect(),
        }
    }
}

impl ComplianceInstance {
    /// Returns the contribution of this compliance instance to the delta message.
    /// Namely, the list of tags as bytes.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for tag in self.tags() {
            msg.extend_from_slice(tag.as_bytes());
        }
        msg
    }

    /// The unit's tags in the order of its resources: the nullifier of a
    /// consumed resource, the commitment of a created resource.
    pub fn tags(&self) -> impl Iterator<Item = Digest> + '_ {
        self.resource_instances.iter().map(|r| r.tag())
    }
}
