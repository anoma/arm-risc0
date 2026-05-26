//! Compliance module containing the compliance instance and witness.

use crate::{
    error::ArmError,
    nullifier_key::NullifierKey,
    resource::{ConsumedResourcePublic, ConsumedResourceWitness, CreatedResourcePublic, Resource},
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
use risc0_zkvm::{
    sha::{Impl as ShaImpl, Sha256},
    Digest,
};

lazy_static! {
    /// The initial root of the empty commitment tree is the hash of an empty string.
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

/// The compliance instance contains all public inputs to the compliance proof.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComplianceInstance {
    /// Public information of consumed resources
    pub consumed_publics: Vec<ConsumedResourcePublic>,
    /// Public information of created resources
    pub created_publics: Vec<CreatedResourcePublic>,
    /// The delta x coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_x: [u32; 8],
    /// The delta y coordinate of the created resource(use u32 array to avoid padding issues in risc0).
    pub delta_y: [u32; 8],
    /// SHA-256 commitment to the kind lookup table supplied with this proof.
    pub kind_table_commitment: Digest,
}

/// An entry in the kind lookup table, mapping (logic_ref, label_ref) to a
/// pre-computed kind point. Avoids hash-to-curve inside the circuit for known
/// resource types.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KindTableEntry {
    /// Logic ref component of the key.
    pub logic_ref: Digest,
    /// Label ref component of the key.
    pub label_ref: Digest,
    /// Uncompressed SEC1-encoded kind point (65 bytes).
    pub kind_point: Vec<u8>,
}

impl KindTableEntry {
    /// Creates a new entry from a (logic_ref, label_ref) key and a pre-computed point.
    pub fn new(logic_ref: Digest, label_ref: Digest, point: &ProjectivePoint) -> Self {
        let encoded = point.to_encoded_point(false);
        KindTableEntry {
            logic_ref,
            label_ref,
            kind_point: encoded.as_bytes().to_vec(),
        }
    }
}

/// The compliance witness contains all private inputs to the compliance proof.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ComplianceWitness {
    /// Private information of consumed resources
    pub consumed_data: Vec<ConsumedResourceWitness>,
    /// Private information of created resources
    pub created_resources: Vec<Resource>,
    /// The existing root for ephemeral resources
    pub ephemeral_root: Digest,
    /// Bytes of randomness for the delta commitment `rcv`
    pub rcv: Vec<u8>,
    /// Optional pre-computed kind points for known resource types.
    /// Maps (logic_ref, label_ref) → uncompressed EC point, skipping hash_to_curve.
    /// Falls back to hash_to_curve for any resource type not present in the table.
    pub kind_table: Vec<KindTableEntry>,
    // TODO: If we want to add function privacy, include:
    // pub input_resource_logic_cm_r: [u8; DATA_BYTES],
    // pub output_resource_logic_cm_r: [u8; DATA_BYTES],
}

impl ComplianceWitness {
    /// Creates a new compliance witness from the given resources. It uses the
    /// initial root for ephemeral resources.
    pub fn from_resources(
        consumed_data: &[ConsumedResourceWitness],
        created_resources: &[Resource],
        kind_table: Vec<KindTableEntry>,
    ) -> Self {
        Self::from_resources_with_ephemeral_root(
            consumed_data,
            created_resources,
            *INITIAL_ROOT,
            kind_table,
        )
    }

    /// Creates a new compliance witness from the given resources and a valid
    /// root when consuming an ephemeral resource.
    pub fn from_resources_with_ephemeral_root(
        consumed_data: &[ConsumedResourceWitness],
        created_resources: &[Resource],
        valid_root: Digest,
        kind_table: Vec<KindTableEntry>,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let rcv = Scalar::random(&mut rng).to_bytes();

        Self::from_parts(
            consumed_data,
            created_resources,
            valid_root,
            rcv.as_ref(),
            kind_table,
        )
    }

    /// Creates a new compliance witness from each of its component parts.
    /// The other constructors are convenience wrappers that fill in defaults.
    fn from_parts(
        consumed_data: &[ConsumedResourceWitness],
        created_resources: &[Resource],
        ephemeral_root: Digest,
        rcv: &[u8],
        kind_table: Vec<KindTableEntry>,
    ) -> ComplianceWitness {
        ComplianceWitness {
            consumed_data: consumed_data.to_vec(),
            created_resources: created_resources.to_vec(),
            ephemeral_root,
            rcv: rcv.to_vec(),
            kind_table,
        }
    }

    /// Looks up the kind point for a resource in the kind table.
    /// Falls back to hash_to_curve if the resource type is not in the table.
    fn lookup_kind(&self, resource: &Resource) -> Result<ProjectivePoint, ArmError> {
        for entry in &self.kind_table {
            if entry.logic_ref == resource.logic_ref && entry.label_ref == resource.label_ref {
                let encoded = EncodedPoint::from_bytes(&entry.kind_point)
                    .map_err(|_| ArmError::InvalidResourceKind)?;
                return ProjectivePoint::from_encoded_point(&encoded)
                    .into_option()
                    .ok_or(ArmError::InvalidResourceKind);
            }
        }
        resource.kind()
    }

    /// Compliance constraints. Produces the public outputs of the unit by
    /// re-computing nullifiers, commitments, tree roots, and the delta
    /// commitment from the witness data.
    ///
    /// Each input resource is touched in a single pass: the same loop over
    /// `consumed_data` (and over `created_resources`) builds the public outputs
    /// and accumulates the (kind, signed-quantity) contributions used for the
    /// delta commitment, so each `commitment()`, `kind()`, and field load
    /// happens once.
    pub fn constrain(&self) -> Result<ComplianceInstance, ArmError> {
        let rcv_scalar = parse_rcv(&self.rcv)?;

        let n_consumed = self.consumed_data.len();
        let n_created = self.created_resources.len();
        let mut consumed_nullifiers = Vec::with_capacity(n_consumed);
        let mut consumed_publics = Vec::with_capacity(n_consumed);
        let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(n_consumed + n_created);
        let mut sums: Vec<Scalar> = Vec::with_capacity(n_consumed + n_created);

        // Constrain consumed resources and accumulate their (kind, +quantity)
        // contributions to the delta.
        for w in &self.consumed_data {
            let resource_commitment = w.resource.commitment();
            let resource_nullifier = w
                .resource
                .nullifier_from_commitment(&w.nf_key, &resource_commitment)?;
            let commitment_tree_root = if w.resource.is_ephemeral {
                self.ephemeral_root
            } else {
                w.cm_merkle_path.root(&resource_commitment)
            };
            // Reading `logic_ref` here forces it to be loaded from memory onto
            // the computational trace.
            consumed_publics.push(ConsumedResourcePublic {
                resource_nullifier,
                resource_logic_ref: w.resource.logic_ref,
                commitment_tree_root,
            });
            consumed_nullifiers.push(resource_nullifier);
            accumulate_kind(
                &mut kinds,
                &mut sums,
                self.lookup_kind(&w.resource)?,
                w.resource.quantity_scalar(),
            );
        }

        // Constrain created resources: re-derive each nonce from the consumed
        // nullifiers, require it to match, and accumulate (kind, -quantity).
        let consumed_nullifiers_digest = Resource::hash_nullifiers(&consumed_nullifiers)?;
        let mut created_publics = Vec::with_capacity(n_created);
        for (resource, index) in self.created_resources.iter().zip(0u32..) {
            if Resource::derive_nonce(index, consumed_nullifiers_digest) != resource.nonce {
                return Err(ArmError::InvalidResourceNonce);
            }
            created_publics.push(CreatedResourcePublic {
                resource_commitment: resource.commitment(),
                resource_logic_ref: resource.logic_ref,
            });
            accumulate_kind(
                &mut kinds,
                &mut sums,
                self.lookup_kind(resource)?,
                -resource.quantity_scalar(),
            );
        }

        // Pedersen commit to the per-kind sums; the binding generators are the
        // kind points themselves, plus the standard generator for `rcv`.
        let delta = kinds
            .iter()
            .zip(sums.iter())
            .fold(ProjectivePoint::IDENTITY, |acc, (kind, sum)| {
                acc + *kind * sum
            })
            + ProjectivePoint::GENERATOR * rcv_scalar;
        let (delta_x, delta_y) = encode_delta(delta)?;
        let kind_table_commitment = self.hash_kind_table();

        Ok(ComplianceInstance {
            consumed_publics,
            created_publics,
            delta_x,
            delta_y,
            kind_table_commitment,
        })
    }

    fn hash_kind_table(&self) -> Digest {
        let mut bytes = Vec::new();
        for entry in &self.kind_table {
            bytes.extend_from_slice(entry.logic_ref.as_bytes());
            bytes.extend_from_slice(entry.label_ref.as_bytes());
            bytes.extend_from_slice(&entry.kind_point);
        }
        *ShaImpl::hash_bytes(&bytes)
    }
}

/// Adds `signed_quantity` to the running sum for `kind`, inserting a new
/// (kind, sum) pair when the kind is seen for the first time.
///
/// The lookup is a linear scan, so this is O(N²) in the number of distinct
/// kinds. That is intentional: in a circuit, a scalar multiplication is far
/// more expensive than a curve-point equality, so trading per-resource scalar
/// mults for a few extra comparisons is the right side of the trade-off for
/// the unit sizes we expect.
fn accumulate_kind(
    kinds: &mut Vec<ProjectivePoint>,
    sums: &mut Vec<Scalar>,
    kind: ProjectivePoint,
    signed_quantity: Scalar,
) {
    if let Some(i) = kinds.iter().position(|k| *k == kind) {
        sums[i] += signed_quantity;
    } else {
        kinds.push(kind);
        sums.push(signed_quantity);
    }
}

/// Decodes the 32-byte `rcv` blob into a scalar.
fn parse_rcv(rcv: &[u8]) -> Result<Scalar, ArmError> {
    let bytes: [u8; 32] = rcv.try_into().map_err(|_| ArmError::InvalidRcv)?;
    Scalar::from_repr(bytes.into())
        .into_option()
        .ok_or(ArmError::InvalidRcv)
}

/// Encodes the affine x/y coordinates of `delta` as `[u32; 8]` arrays.
fn encode_delta(delta: ProjectivePoint) -> Result<([u32; 8], [u32; 8]), ArmError> {
    let encoded = delta.to_encoded_point(false);
    let delta_x: [u32; 8] = bytes_to_words(encoded.x().ok_or(ArmError::InvalidDelta)?)
        .try_into()
        .map_err(|_| ArmError::InvalidDelta)?;
    let delta_y: [u32; 8] = bytes_to_words(encoded.y().ok_or(ArmError::InvalidDelta)?)
        .try_into()
        .map_err(|_| ArmError::InvalidDelta)?;
    Ok((delta_x, delta_y))
}

impl Default for ComplianceWitness {
    /// The default value is meaningless and only for testing.
    /// It contains three consumed and two created resources.
    fn default() -> Self {
        let consumed_data = vec![ConsumedResourceWitness::default(); 3];

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

        ComplianceWitness {
            consumed_data,
            created_resources: vec![make_created(nonce_0), make_created(nonce_1)],
            ephemeral_root: *INITIAL_ROOT,
            rcv: Scalar::ONE.to_bytes().to_vec(),
            kind_table: vec![],
        }
    }
}

impl ComplianceInstance {
    /// Returns the delta as a projective point. It fails if the delta is not a valid point.
    pub fn delta_projective(&self) -> Result<ProjectivePoint, ArmError> {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            words_to_bytes(&self.delta_x).into(),
            words_to_bytes(&self.delta_y).into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }

    /// Returns the contribution of this compliance instance to the delta message.
    /// Namely, the list of tags as bytes.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for tag in self.tags() {
            msg.extend_from_slice(tag.as_bytes());
        }
        msg
    }

    /// Canonical ordering of the unit's tags: consumed nullifiers first, then
    /// created commitments. Both the action tree and the per-resource logic
    /// verifier proofs MUST be built against this order; any other ordering
    /// will produce a different action-tree root and verification will fail.
    pub fn tags(&self) -> impl Iterator<Item = Digest> + '_ {
        self.consumed_publics
            .iter()
            .map(|r| r.resource_nullifier)
            .chain(self.created_publics.iter().map(|r| r.resource_commitment))
    }
}
