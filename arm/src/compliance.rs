//! Host-engine operations for the compliance unit: randomized witness
//! construction, the compliance constraints (`constrain`), and delta-point
//! decoding — everything requiring k256 or randomness. The instance and
//! witness types themselves live in `anoma-rm-core` and are re-exported
//! here unchanged.

pub use arm_core::compliance::*;

use crate::error::ArmError;
use crate::resource::{
    ConsumedResourcePublic, ConsumedResourceWitness, CreatedResourcePublic, Resource,
};
use crate::utils::{bytes_to_words, words_to_bytes};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};
use risc0_zkvm::Digest;

/// Creates a new entry from a (logic_ref, label_ref) key and a pre-computed point.
pub fn kind_table_entry(
    logic_ref: Digest,
    label_ref: Digest,
    point: &ProjectivePoint,
) -> KindTableEntry {
    let encoded = point.to_encoded_point(false);
    KindTableEntry {
        logic_ref,
        label_ref,
        kind_point: encoded.as_bytes().to_vec(),
    }
}

/// Creates a new compliance witness from the given resources with a freshly
/// drawn `rcv`. It uses the initial root for ephemeral resources.
pub fn from_resources(
    consumed_data: &[ConsumedResourceWitness],
    created_resources: &[Resource],
    kind_table: Vec<KindTableEntry>,
) -> ComplianceWitness {
    from_resources_with_ephemeral_root(consumed_data, created_resources, INITIAL_ROOT, kind_table)
}

/// Creates a new compliance witness from the given resources with a freshly
/// drawn `rcv` and a valid root when consuming an ephemeral resource.
pub fn from_resources_with_ephemeral_root(
    consumed_data: &[ConsumedResourceWitness],
    created_resources: &[Resource],
    valid_root: Digest,
    kind_table: Vec<KindTableEntry>,
) -> ComplianceWitness {
    let mut rng = rand::thread_rng();
    let rcv = Scalar::random(&mut rng).to_bytes();

    ComplianceWitness::from_parts(
        consumed_data,
        created_resources,
        valid_root,
        rcv.as_ref(),
        kind_table,
    )
}

/// Looks up the kind point for a resource in the witness's kind table.
/// Falls back to hash_to_curve if the resource type is not in the table.
fn lookup_kind(
    witness: &ComplianceWitness,
    resource: &Resource,
) -> Result<ProjectivePoint, ArmError> {
    for entry in &witness.kind_table {
        if entry.logic_ref == resource.logic_ref && entry.label_ref == resource.label_ref {
            let encoded = EncodedPoint::from_bytes(&entry.kind_point)
                .map_err(|_| ArmError::InvalidResourceKind)?;
            return ProjectivePoint::from_encoded_point(&encoded)
                .into_option()
                .ok_or(ArmError::InvalidResourceKind);
        }
    }
    crate::resource::kind(resource)
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
    let mut consumed_nullifiers = Vec::with_capacity(n_consumed);
    let mut consumed_publics = Vec::with_capacity(n_consumed);
    let mut kinds: Vec<ProjectivePoint> = Vec::with_capacity(n_consumed + n_created);
    let mut sums: Vec<Scalar> = Vec::with_capacity(n_consumed + n_created);

    // Constrain consumed resources and accumulate their (kind, +quantity)
    // contributions to the delta.
    for w in &witness.consumed_data {
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
            lookup_kind(witness, &w.resource)?,
            crate::resource::quantity_scalar(&w.resource),
        );
    }

    // Constrain created resources: re-derive each nonce from the consumed
    // nullifiers, require it to match, and accumulate (kind, -quantity).
    let consumed_nullifiers_digest = Resource::hash_nullifiers(&consumed_nullifiers)?;
    let mut created_publics = Vec::with_capacity(n_created);
    for (resource, index) in witness.created_resources.iter().zip(0u32..) {
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
            lookup_kind(witness, resource)?,
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
    let kind_table_commitment = hash_kind_table_entries(&witness.kind_table);

    Ok(ComplianceInstance {
        consumed_publics,
        created_publics,
        delta_x,
        delta_y,
        kind_table_commitment,
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
