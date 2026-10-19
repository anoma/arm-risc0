//! Host-engine operations for the compliance unit: randomized witness
//! construction, the compliance constraints (`constrain`), and delta-point
//! decoding — everything requiring k256 or randomness. The instance and
//! witness types themselves live in `anoma-rm-core` and are re-exported
//! here unchanged.

pub use arm_core::compliance::*;

use crate::error::ArmError;
use crate::resource::{Resource, ResourcePublic, ResourceWitness};
use crate::utils::{bytes_to_words, words_to_bytes};
use crate::Digest;
#[cfg(feature = "transaction")]
use k256::elliptic_curve::Field;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};

/// Creates a new compliance witness from the given resources, in their order,
/// with a freshly drawn `rcv`. It uses the initial root for ephemeral resources.
#[cfg(feature = "transaction")]
pub fn from_resources(
    resources: Vec<ResourceWitness>,
    kind_table: &crate::kind_table::KindTable,
) -> ComplianceWitness {
    from_resources_with_ephemeral_root(resources, INITIAL_ROOT, kind_table)
}

/// Creates a new compliance witness from the given resources, in their order,
/// with a freshly drawn `rcv` and a valid root when consuming an ephemeral
/// resource.
#[cfg(feature = "transaction")]
pub fn from_resources_with_ephemeral_root(
    resources: Vec<ResourceWitness>,
    valid_root: Digest,
    kind_table: &crate::kind_table::KindTable,
) -> ComplianceWitness {
    let mut rng = rand::thread_rng();
    let rcv = Scalar::random(&mut rng).to_bytes();

    let kind_paths = kind_table.kind_paths_for(&resources);

    ComplianceWitness::from_parts(resources, valid_root, rcv.as_ref(), kind_paths)
}

/// Decodes the kind point from a `KindPath`, verifying its Merkle path
/// against `derived_root` (updated in place on first use). Falls back to
/// `hash_to_curve` when `kind_path` is `None`.
fn resolve_kind(
    kind_path: Option<&KindPath>,
    resource: &Resource,
    derived_root: &mut Option<Digest>,
) -> Result<ProjectivePoint, ArmError> {
    match kind_path {
        Some(kp) => {
            let leaf =
                arm_core::compliance::hash_kind_table_leaf(&arm_core::compliance::KindTableEntry {
                    logic_ref: resource.logic_ref,
                    label_ref: resource.label_ref,
                    kind_point: kp.kind_point.clone(),
                });
            let path_root = kp.path.root(&leaf);
            match *derived_root {
                None => *derived_root = Some(path_root),
                Some(r) if r != path_root => return Err(ArmError::InvalidResourceKind),
                _ => {}
            }
            let encoded = EncodedPoint::from_bytes(&kp.kind_point)
                .map_err(|_| ArmError::InvalidResourceKind)?;
            ProjectivePoint::from_encoded_point(&encoded)
                .into_option()
                .ok_or(ArmError::InvalidResourceKind)
        }
        None => crate::resource::kind(resource),
    }
}

/// Compliance constraints. Produces the public outputs of the unit, in the
/// order of the witness resources, by re-computing nullifiers, commitments,
/// tree roots, and the delta commitment from the witness data.
///
/// Each resource is touched in a single pass that builds its public output
/// and accumulates its (kind, signed-quantity) contribution to the delta
/// commitment, so each `commitment()`, `kind()`, and field load happens
/// once. The nonces of the created resources derive from all consumed
/// nullifiers, so they are checked after that pass.
pub fn constrain(witness: &ComplianceWitness) -> Result<ComplianceInstance, ArmError> {
    let rcv_scalar = parse_rcv(&witness.rcv)?;

    let n_resources = witness.resources.len();

    if witness.kind_paths.len() != n_resources {
        return Err(ArmError::InvalidResourceKind);
    }

    // The kind_table_root committed in the instance is derived from the paths:
    // the root of the first non-None path, or PADDING_LEAF if all are None.
    let mut derived_root: Option<Digest> = None;

    let mut consumed_nullifiers = Vec::with_capacity(n_resources);
    let mut resource_publics = Vec::with_capacity(n_resources);
    let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(n_resources);
    let mut sums: Vec<Scalar> = Vec::with_capacity(n_resources);

    // Constrain the resources and accumulate their contributions to the delta:
    // (kind, +quantity) for a consumed resource, (kind, -quantity) for a
    // created one.
    for (resource_witness, kind_path) in witness.resources.iter().zip(&witness.kind_paths) {
        let resource = resource_witness.resource();
        let resource_commitment = resource.commitment();
        let (resource_tag, commitment_tree_root, signed_quantity) = match resource_witness {
            ResourceWitness::Consumed(w) => {
                let resource_nullifier =
                    resource.nullifier_from_commitment(&w.nf_key, &resource_commitment)?;
                let commitment_tree_root = if resource.is_ephemeral {
                    witness.ephemeral_root
                } else {
                    w.cm_merkle_path.root(&resource_commitment)
                };
                consumed_nullifiers.push(resource_nullifier);
                (
                    resource_nullifier,
                    Some(commitment_tree_root),
                    crate::resource::quantity_scalar(resource),
                )
            }
            ResourceWitness::Created(_) => (
                resource_commitment,
                None,
                -crate::resource::quantity_scalar(resource),
            ),
        };
        // Reading `logic_ref` here forces it to be loaded from memory onto
        // the computational trace.
        resource_publics.push(ResourcePublic {
            resource_tag,
            resource_logic_ref: resource.logic_ref,
            commitment_tree_root,
        });
        accumulate_kind(
            &mut kinds,
            &mut sums,
            resolve_kind(kind_path.as_ref(), resource, &mut derived_root)?,
            signed_quantity,
        );
    }

    // Re-derive each created nonce from its index among the created resources
    // and the consumed nullifiers, and require it to match.
    let consumed_nullifiers_digest = Resource::hash_nullifiers(&consumed_nullifiers)?;
    let created_resources = witness.resources.iter().filter_map(|r| match r {
        ResourceWitness::Consumed(_) => None,
        ResourceWitness::Created(resource) => Some(resource),
    });
    for (j, resource) in created_resources.enumerate() {
        if Resource::derive_nonce(j as u32, consumed_nullifiers_digest) != resource.nonce {
            return Err(ArmError::InvalidResourceNonce);
        }
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

    let kind_table_root = derived_root.unwrap_or(arm_core::merkle_path::PADDING_LEAF);

    Ok(ComplianceInstance {
        resource_publics,
        delta_x,
        delta_y,
        kind_table_root,
    })
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

/// Returns the delta of a compliance instance as a projective point.
/// It fails if the delta is not a valid point.
pub fn delta_projective(instance: &ComplianceInstance) -> Result<ProjectivePoint, ArmError> {
    let encoded_point = EncodedPoint::from_affine_coordinates(
        words_to_bytes(&instance.delta_x).into(),
        words_to_bytes(&instance.delta_y).into(),
        false,
    );
    ProjectivePoint::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or(ArmError::InvalidDelta)
}
