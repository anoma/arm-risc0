//! Host-engine operations for the compliance unit: randomized witness
//! construction, the compliance constraints (`constrain`), and delta-point
//! decoding — everything requiring k256 or randomness. The instance and
//! witness types themselves live in `anoma-rm-core` and are re-exported
//! here unchanged.

pub use arm_core::compliance::*;

use crate::error::ArmError;
#[cfg(feature = "transaction")]
use crate::resource::ConsumedResourceWitness;
use crate::resource::{ConsumedResourcePublic, CreatedResourcePublic, Resource};
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

/// Creates a new compliance witness from the given resources with a freshly
/// drawn `rcv`. It uses the initial root for ephemeral resources.
#[cfg(feature = "transaction")]
pub fn from_resources(
    consumed_data: Vec<ConsumedResourceWitness>,
    created_resources: Vec<Resource>,
    kind_table: &crate::kind_table::KindTable,
) -> ComplianceWitness {
    from_resources_with_ephemeral_root(consumed_data, created_resources, INITIAL_ROOT, kind_table)
}

/// Creates a new compliance witness from the given resources with a freshly
/// drawn `rcv` and a valid root when consuming an ephemeral resource.
#[cfg(feature = "transaction")]
pub fn from_resources_with_ephemeral_root(
    consumed_data: Vec<ConsumedResourceWitness>,
    created_resources: Vec<Resource>,
    valid_root: Digest,
    kind_table: &crate::kind_table::KindTable,
) -> ComplianceWitness {
    let mut rng = rand::thread_rng();
    let rcv = Scalar::random(&mut rng).to_bytes();

    let kind_paths = kind_table.kind_paths_for(&consumed_data, &created_resources);

    ComplianceWitness::from_parts(
        consumed_data,
        created_resources,
        valid_root,
        rcv.as_ref(),
        kind_paths,
    )
}

/// Decodes the kind point from a `KindPath`, verifying its Merkle path
/// against `derived_root` (updated in place on first use). Falls back to
/// `hash_to_curve` when `kind_path` is `None`.
///
/// The kind point must be uncompressed SEC1 (65 bytes, leading `0x04`), the
/// only encoding the host loader accepts (`kind_table::validate_kind_point`).
/// That rules out the identity, whose encoding is the single byte `0x00`.
fn resolve_kind(
    kind_path: Option<&KindPath>,
    resource: &Resource,
    derived_root: &mut Option<Digest>,
) -> Result<ProjectivePoint, ArmError> {
    match kind_path {
        Some(kp) => {
            if kp.kind_point.len() != 65 || kp.kind_point[0] != 0x04 {
                return Err(ArmError::InvalidResourceKind);
            }
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

/// Compliance constraints. Produces the public outputs of the unit by
/// re-computing nullifiers, commitments, tree roots, and the delta
/// commitment from the witness data.
///
/// Each input resource is touched in a single pass: the same loop over
/// `consumed_data` (and over `created_resources`) builds the public outputs
/// and accumulates the (kind, signed-quantity) contributions used for the
/// delta commitment, so each `commitment()`, `kind()`, and field load
/// happens once.
pub fn constrain(witness: &ComplianceWitness) -> Result<ComplianceInstance, ArmError> {
    let rcv_scalar = parse_rcv(&witness.rcv)?;

    let n_consumed = witness.consumed_data.len();
    let n_created = witness.created_resources.len();

    if witness.kind_paths.len() != n_consumed + n_created {
        return Err(ArmError::InvalidResourceKind);
    }

    // The kind_table_root committed in the instance is derived from the paths:
    // the root of the first non-None path, or PADDING_LEAF if all are None.
    let mut derived_root: Option<Digest> = None;

    let mut consumed_nullifiers = Vec::with_capacity(n_consumed);
    let mut consumed_publics = Vec::with_capacity(n_consumed);
    let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(n_consumed + n_created);
    let mut sums: Vec<Scalar> = Vec::with_capacity(n_consumed + n_created);

    // Constrain consumed resources and accumulate their (kind, +quantity)
    // contributions to the delta.
    for (i, w) in witness.consumed_data.iter().enumerate() {
        let resource_commitment = w.resource.commitment();
        let resource_nullifier = w
            .resource
            .nullifier_from_commitment(&w.nf_key, &resource_commitment)?;
        let commitment_tree_root = if w.resource.is_ephemeral {
            witness.ephemeral_root
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
            resolve_kind(
                witness.kind_paths[i].as_ref(),
                &w.resource,
                &mut derived_root,
            )?,
            crate::resource::quantity_scalar(&w.resource),
        );
    }

    // Constrain created resources: re-derive each nonce from the consumed
    // nullifiers, require it to match, and accumulate (kind, -quantity).
    let consumed_nullifiers_digest = Resource::hash_nullifiers(&consumed_nullifiers)?;
    let mut created_publics = Vec::with_capacity(n_created);
    for (j, resource) in witness.created_resources.iter().enumerate() {
        if Resource::derive_nonce(j as u32, consumed_nullifiers_digest) != resource.nonce {
            return Err(ArmError::InvalidResourceNonce);
        }
        created_publics.push(CreatedResourcePublic {
            resource_commitment: resource.commitment(),
            resource_logic_ref: resource.logic_ref,
        });
        accumulate_kind(
            &mut kinds,
            &mut sums,
            resolve_kind(
                witness.kind_paths[n_consumed + j].as_ref(),
                resource,
                &mut derived_root,
            )?,
            -crate::resource::quantity_scalar(resource),
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

    let kind_table_root = derived_root.unwrap_or(arm_core::merkle_path::PADDING_LEAF);

    Ok(ComplianceInstance {
        consumed_publics,
        created_publics,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path::MerklePath;
    use crate::nullifier_key::NullifierKey;
    use crate::resource::ConsumedResourceWitness;

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
    /// `quantity` of a kind whose path opens a leaf holding `kind_point`. The
    /// tree is that one leaf, so the path is empty.
    fn witness(kind_point: Vec<u8>, quantity: u128) -> ComplianceWitness {
        let nf_key = NullifierKey::default();
        let consumed = resource(2, 0, [0u8; 32]);
        let nullifier = consumed.nullifier(&nf_key).unwrap();
        let nonce = Resource::derive_nonce(0, Resource::hash_nullifiers(&[nullifier]).unwrap());
        ComplianceWitness::from_parts(
            vec![ConsumedResourceWitness::from_resource(consumed, nf_key)],
            vec![resource(3, quantity, nonce)],
            INITIAL_ROOT,
            &RCV,
            vec![
                None,
                Some(KindPath {
                    kind_point,
                    path: MerklePath::empty(),
                }),
            ],
        )
    }

    /// The identity has a SEC1 encoding, the single byte `0x00`. A path to a
    /// leaf holding it is rejected, so no created resource can add nothing to
    /// the delta.
    #[test]
    fn identity_kind_point_is_rejected() {
        assert_eq!(
            constrain(&witness(vec![0x00], 1_000_000)).map(|_| ()),
            Err(ArmError::InvalidResourceKind)
        );
    }
}
