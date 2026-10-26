//! Host-engine operations for the compliance unit: randomized witness
//! construction, the compliance constraints (`constrain`), and delta-point
//! decoding — everything requiring k256 or randomness. The instance and
//! witness types themselves live in `anoma-rm-core` and are re-exported
//! here unchanged.

pub use arm_core::compliance::*;

use crate::error::ArmError;
use crate::resource::{ComplianceResourceInstance, Resource, ResourceWitness};
use crate::utils::bytes_to_words;
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
    kind_tree: &crate::kind_tree::KindTree,
) -> ComplianceWitness {
    from_resources_with_ephemeral_root(resources, INITIAL_ROOT, kind_tree)
}

/// Creates a new compliance witness from the given resources, in their order,
/// with a freshly drawn `rcv` and a valid root when consuming an ephemeral
/// resource.
#[cfg(feature = "transaction")]
pub fn from_resources_with_ephemeral_root(
    resources: Vec<ResourceWitness>,
    valid_root: Digest,
    kind_tree: &crate::kind_tree::KindTree,
) -> ComplianceWitness {
    let mut rng = rand::thread_rng();
    let rcv = Scalar::random(&mut rng).to_bytes();

    let kind_paths = kind_tree.kind_paths_for(&resources);

    ComplianceWitness::from_parts(resources, valid_root, rcv.as_ref(), kind_paths)
}

/// Decodes the kind base from a `KindPath`, verifying its Merkle path
/// against `derived_root` (updated in place on first use). Falls back to
/// `hash_to_curve` when `kind_path` is `None`.
///
/// The kind base must be uncompressed SEC1 (65 bytes, leading `0x04`), the
/// only encoding the host loader accepts (`kind_tree::validate_kind_base`).
/// That rules out the identity, whose encoding is the single byte `0x00`.
fn resolve_kind(
    kind_path: Option<&KindPath>,
    resource: &Resource,
    derived_root: &mut Option<Digest>,
    position: usize,
) -> Result<ProjectivePoint, ArmError> {
    match kind_path {
        Some(kp) => {
            if kp.kind_base.len() != 65 || kp.kind_base[0] != 0x04 {
                return Err(ArmError::InvalidKindBaseEncoding { position });
            }
            let leaf =
                arm_core::compliance::hash_kind_tree_leaf(&arm_core::compliance::KindTreeEntry {
                    logic_ref: resource.logic_ref,
                    label_ref: resource.label_ref,
                    kind_base: kp.kind_base.clone(),
                });
            let path_root = kp.path.root(&leaf);
            match *derived_root {
                None => *derived_root = Some(path_root),
                Some(r) if r != path_root => {
                    return Err(ArmError::KindPathRootMismatch {
                        position,
                        expected: r,
                        found: path_root,
                    })
                }
                _ => {}
            }
            let encoded = EncodedPoint::from_bytes(&kp.kind_base)
                .map_err(|_| ArmError::KindBaseNotOnCurve { position })?;
            ProjectivePoint::from_encoded_point(&encoded)
                .into_option()
                .ok_or(ArmError::KindBaseNotOnCurve { position })
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

    let n_resources = witness.resource_instances.len();

    if witness.kind_paths.len() != n_resources {
        return Err(ArmError::KindPathCountMismatch {
            expected: n_resources,
            found: witness.kind_paths.len(),
        });
    }

    // The kind_tree_root committed in the instance is derived from the paths:
    // the root of the first non-None path, or PADDING_LEAF if all are None.
    let mut derived_root: Option<Digest> = None;

    let mut consumed_nullifiers = Vec::with_capacity(n_resources);
    let mut resources = Vec::with_capacity(n_resources);
    let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(n_resources);
    let mut sums: Vec<Scalar> = Vec::with_capacity(n_resources);

    // Constrain the resources and accumulate their contributions to the delta:
    // (kind, +quantity) for a consumed resource, (kind, -quantity) for a
    // created one.
    for (position, (resource_witness, kind_path)) in witness
        .resource_instances
        .iter()
        .zip(&witness.kind_paths)
        .enumerate()
    {
        let resource = resource_witness.resource();
        let resource_commitment = resource.commitment();
        // Reading `logic_ref` here forces it to be loaded from memory onto
        // the computational trace.
        let (resource_instance, signed_quantity) = match resource_witness {
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
                    ComplianceResourceInstance::Consumed {
                        nullifier: resource_nullifier,
                        logic_ref: resource.logic_ref,
                        commitment_tree_root,
                    },
                    crate::resource::quantity_scalar(resource),
                )
            }
            ResourceWitness::Created(_) => (
                ComplianceResourceInstance::Created {
                    commitment: resource_commitment,
                    logic_ref: resource.logic_ref,
                },
                -crate::resource::quantity_scalar(resource),
            ),
        };
        resources.push(resource_instance);
        accumulate_kind(
            &mut kinds,
            &mut sums,
            resolve_kind(kind_path.as_ref(), resource, &mut derived_root, position)?,
            signed_quantity,
        );
    }

    // Re-derive each created nonce from its index among the created resources
    // and the consumed nullifiers, and require it to match.
    let consumed_nullifiers_digest = Resource::hash_nullifiers(&consumed_nullifiers)?;
    let created_resources = witness.resource_instances.iter().filter_map(|r| match r {
        ResourceWitness::Consumed(_) => None,
        ResourceWitness::Created(resource) => Some(resource),
    });
    for (j, resource) in created_resources.enumerate() {
        if Resource::derive_nonce(j as u32, consumed_nullifiers_digest) != resource.nonce {
            return Err(ArmError::InvalidResourceNonce);
        }
    }

    // Pedersen commit to the per-kind sums; the binding generators are the
    // kind bases themselves, plus the standard generator for `rcv`.
    let delta = kinds
        .iter()
        .zip(sums.iter())
        .fold(ProjectivePoint::IDENTITY, |acc, (kind, sum)| {
            acc + *kind * sum
        })
        + ProjectivePoint::GENERATOR * rcv_scalar;
    let (delta_x, delta_y) = encode_delta(delta)?;

    let kind_tree_root = derived_root.unwrap_or(arm_core::merkle_path::PADDING_LEAF);

    Ok(ComplianceInstance {
        resource_instances: resources,
        delta_x,
        delta_y,
        kind_tree_root,
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
    crate::aggregation_instance::delta_projective_from_words(&instance.delta_x, &instance.delta_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::MerklePath;
    use crate::nullifier_key::NullifierKey;
    use crate::resource::ResourceWitnessConsumed;

    const RCV: [u8; 32] = [1u8; 32];

    fn resource(label: u8, quantity: u128, nonce: [u8; 32]) -> Resource {
        Resource {
            logic_ref: Digest::from([1u8; 32]),
            label_ref: Digest::from([label; 32]),
            quantity,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce,
            nk_commitment: NullifierKey::default().commit(),
            rand_seed: [0u8; 32],
        }
    }

    /// A unit that consumes an ephemeral resource of quantity 0 and creates
    /// `quantity` of a kind whose path opens a leaf holding `kind_base`. The
    /// tree is that one leaf, so the path is empty.
    fn witness(kind_base: Vec<u8>, quantity: u128) -> ComplianceWitness {
        let nf_key = NullifierKey::default();
        let consumed = resource(2, 0, [0u8; 32]);
        let nullifier = consumed.nullifier(&nf_key).unwrap();
        let nonce = Resource::derive_nonce(0, Resource::hash_nullifiers(&[nullifier]).unwrap());
        ComplianceWitness::from_parts(
            vec![
                ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource(consumed, nf_key)),
                ResourceWitness::Created(resource(3, quantity, nonce)),
            ],
            INITIAL_ROOT,
            &RCV,
            vec![
                None,
                Some(KindPath {
                    kind_base,
                    path: MerklePath::empty(),
                }),
            ],
        )
    }

    /// The identity has a SEC1 encoding, the single byte `0x00`. A path to a
    /// leaf holding it is rejected, so no created resource can add nothing to
    /// the delta. Position 1 is the created resource: the consumed one at
    /// position 0 carries no path.
    #[test]
    fn identity_kind_base_is_rejected() {
        assert_eq!(
            constrain(&witness(vec![0x00], 1_000_000)).map(|_| ()),
            Err(ArmError::InvalidKindBaseEncoding { position: 1 })
        );
    }

    #[test]
    fn kind_path_count_mismatch_is_rejected() {
        let mut w = witness(vec![0x00], 1_000_000);
        w.kind_paths.pop();
        assert_eq!(
            constrain(&w).map(|_| ()),
            Err(ArmError::KindPathCountMismatch {
                expected: 2,
                found: 1
            })
        );
    }

    /// Both resources carry a path, to leaves for two different labels. The
    /// consumed resource at position 0 sets the root, so position 1 fails.
    #[test]
    fn kind_paths_under_different_roots_are_rejected() {
        let generator = k256::AffinePoint::GENERATOR
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut w = witness(generator.clone(), 1_000_000);
        w.kind_paths[0] = Some(KindPath {
            kind_base: generator,
            path: MerklePath::empty(),
        });
        assert!(matches!(
            constrain(&w),
            Err(ArmError::KindPathRootMismatch { position: 1, expected, found }) if expected != found
        ));
    }
}
