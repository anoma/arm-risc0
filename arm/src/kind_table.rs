//! `KindTable`: a Merkle tree over pre-computed kind points for known resource
//! types, used to skip `hash_to_curve` inside the compliance circuit.

use crate::{
    compliance::{hash_kind_table_leaf, KindPath, KindTableEntry},
    error::ArmError,
    resource::{ConsumedResourceWitness, Resource},
    Digest,
};
use arm_core::merkle_path::{MerklePath, PADDING_LEAF};
use arm_core::utils::hash_two;

/// A Merkle kind table: a fixed binary tree over known `(logic_ref, label_ref)`
/// → kind-point mappings that lets a compliance witness skip `hash_to_curve`
/// for well-known resource types.
///
/// **Tree construction** — entries are sorted lexicographically by
/// `(logic_ref, label_ref)` bytes so that host-side path computation is
/// deterministic regardless of insertion order. Duplicate `(logic_ref,
/// label_ref)` pairs are rejected. Leaf `i` is
/// `hash_kind_table_leaf(&entries[i])`. The leaf layer is padded to the next
/// power of two with `PADDING_LEAF`; internal nodes are `hash_two(left,
/// right)`. An empty table has root `PADDING_LEAF`.
///
/// **In-circuit verification** — `constrain()` derives the committed
/// `kind_table_root` from the paths supplied in `ComplianceWitness.kind_paths`:
/// each non-`None` path must produce the same root via `MerklePath::root(leaf)`,
/// and the prover has no freedom to choose a different root.
pub struct KindTable {
    entries: Vec<KindTableEntry>,
    root: Digest,
    /// Pre-computed leaf hashes in the same order as `entries`.
    leaves: Vec<Digest>,
}

impl KindTable {
    /// Returns a `KindTable` with no entries. All resources fall back to
    /// `hash_to_curve`; the committed root is `PADDING_LEAF`.
    pub fn empty() -> KindTable {
        KindTable {
            entries: Vec::new(),
            root: PADDING_LEAF,
            leaves: Vec::new(),
        }
    }

    /// Builds a `KindTable` from a list of entries, validating every kind
    /// point, rejecting duplicates, and sorting by `(logic_ref, label_ref)`.
    pub fn from_entries(mut entries: Vec<KindTableEntry>) -> Result<KindTable, ArmError> {
        for entry in &entries {
            validate_kind_point(&entry.kind_point)?;
        }
        entries.sort_by(|a, b| {
            a.logic_ref
                .as_bytes()
                .cmp(b.logic_ref.as_bytes())
                .then_with(|| a.label_ref.as_bytes().cmp(b.label_ref.as_bytes()))
        });
        if entries
            .windows(2)
            .any(|w| w[0].logic_ref == w[1].logic_ref && w[0].label_ref == w[1].label_ref)
        {
            return Err(ArmError::KindTableLoadFailed);
        }
        let leaves: Vec<Digest> = entries.iter().map(hash_kind_table_leaf).collect();
        let root = merkle_root(&leaves);
        Ok(KindTable {
            entries,
            root,
            leaves,
        })
    }

    /// The Merkle root committed to in every `ComplianceInstance.kind_table_root`.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// The sorted entries.
    pub fn entries(&self) -> &[KindTableEntry] {
        &self.entries
    }

    /// Returns the `KindPath` for `(logic_ref, label_ref)`, or `None` if the
    /// pair is not in the table.
    pub fn kind_path_for(&self, logic_ref: &Digest, label_ref: &Digest) -> Option<KindPath> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.logic_ref == *logic_ref && e.label_ref == *label_ref)?;
        let kind_point = self.entries[pos].kind_point.clone();
        let path = merkle_path(&self.leaves, pos);
        Some(KindPath { kind_point, path })
    }

    /// Returns one `Option<KindPath>` per resource (consumed first, then
    /// created), matching the indexing `constrain()` expects in
    /// `ComplianceWitness.kind_paths`.
    pub fn kind_paths_for(
        &self,
        consumed_data: &[ConsumedResourceWitness],
        created_resources: &[Resource],
    ) -> Vec<Option<KindPath>> {
        consumed_data
            .iter()
            .map(|w| self.kind_path_for(&w.resource.logic_ref, &w.resource.label_ref))
            .chain(
                created_resources
                    .iter()
                    .map(|r| self.kind_path_for(&r.logic_ref, &r.label_ref)),
            )
            .collect()
    }
}

/// Computes the Merkle root of `leaves` padded to the next power of two with
/// `PADDING_LEAF`. Returns `PADDING_LEAF` for an empty list.
fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return PADDING_LEAF;
    }
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<Digest> = leaves.to_vec();
    layer.resize(n, PADDING_LEAF);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|c| hash_two(&c[0], &c[1])).collect();
    }
    layer[0]
}

/// Computes the Merkle authentication path for `leaves[pos]`.
/// Each entry is `(sibling_digest, leaf_is_right_child)`, matching the
/// convention in `MerklePath::root()`: `false` means the current node is the
/// left child (so `hash_two(current, sibling)`), `true` means it is the right
/// child (so `hash_two(sibling, current)`).
/// Validates that `bytes` is a well-formed uncompressed SEC1 secp256k1 point:
/// 65 bytes, leading 0x04 byte, and on the curve.
pub(crate) fn validate_kind_point(bytes: &[u8]) -> Result<(), ArmError> {
    use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ArmError::KindTableLoadFailed);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| ArmError::KindTableLoadFailed)?;
    if ProjectivePoint::from_encoded_point(&encoded)
        .is_none()
        .into()
    {
        return Err(ArmError::KindTableLoadFailed);
    }
    Ok(())
}

fn merkle_path(leaves: &[Digest], pos: usize) -> MerklePath {
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<Digest> = leaves.to_vec();
    layer.resize(n, PADDING_LEAF);

    let mut path = Vec::new();
    let mut idx = pos;
    while layer.len() > 1 {
        let is_right_child = idx % 2 == 1;
        let sibling_idx = if is_right_child { idx - 1 } else { idx + 1 };
        path.push((layer[sibling_idx], is_right_child));
        idx /= 2;
        layer = layer.chunks(2).map(|c| hash_two(&c[0], &c[1])).collect();
    }
    MerklePath::from_path(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::hash_kind_table_leaf;

    /// A valid uncompressed secp256k1 generator point (G), used as a
    /// stand-in kind point in unit tests. 65 bytes, leading 0x04.
    fn generator_point() -> Vec<u8> {
        hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .unwrap()
    }

    fn entry(logic_byte: u8, label_byte: u8) -> KindTableEntry {
        let mut logic = [0u8; 32];
        logic[31] = logic_byte;
        let mut label = [0u8; 32];
        label[31] = label_byte;
        KindTableEntry {
            logic_ref: Digest::from(logic),
            label_ref: Digest::from(label),
            kind_point: generator_point(),
        }
    }

    // ── construction ──────────────────────────────────────────────────────────

    #[test]
    fn empty_table_has_padding_leaf_root() {
        assert_eq!(KindTable::empty().root(), PADDING_LEAF);
    }

    #[test]
    fn single_entry_root_equals_its_leaf_hash() {
        let e = entry(1, 0);
        let leaf = hash_kind_table_leaf(&e);
        let kt = KindTable::from_entries(vec![e]).unwrap();
        // next_power_of_two(1) == 1: the layer is already width-1, so no
        // padding occurs and the root is the leaf itself.
        assert_eq!(kt.root(), leaf);
    }

    #[test]
    fn rejects_invalid_kind_point() {
        let mut e = entry(1, 0);
        e.kind_point = vec![0u8; 65]; // all-zero is not a valid curve point
        assert!(KindTable::from_entries(vec![e]).is_err());
    }

    #[test]
    fn rejects_duplicate_logic_label_pair() {
        let entries = vec![entry(1, 0), entry(1, 0)];
        assert!(
            KindTable::from_entries(entries).is_err(),
            "duplicate (logic_ref, label_ref) must be rejected"
        );
    }

    #[test]
    fn insertion_order_does_not_affect_root() {
        let e1 = entry(1, 0);
        let e2 = entry(2, 0);
        let e3 = entry(3, 0);

        let kt_abc = KindTable::from_entries(vec![e1.clone(), e2.clone(), e3.clone()]).unwrap();
        let kt_cba = KindTable::from_entries(vec![e3.clone(), e2.clone(), e1.clone()]).unwrap();
        let kt_bca = KindTable::from_entries(vec![e2.clone(), e3.clone(), e1.clone()]).unwrap();

        assert_eq!(kt_abc.root(), kt_cba.root());
        assert_eq!(kt_abc.root(), kt_bca.root());
    }

    // ── path generation ───────────────────────────────────────────────────────

    #[test]
    fn all_paths_reconstruct_root_power_of_two() {
        // Four entries — exact power of two, no padding needed at the leaf layer.
        let entries: Vec<_> = (1u8..=4).map(|i| entry(i, 0)).collect();
        let kt = KindTable::from_entries(entries.clone()).unwrap();
        let root = kt.root();

        for e in &entries {
            let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
            let leaf = hash_kind_table_leaf(e);
            assert_eq!(kp.path.root(&leaf), root, "path did not reconstruct root");
        }
    }

    #[test]
    fn all_paths_reconstruct_root_non_power_of_two() {
        // Three entries pad to four; last entry's sibling at the bottom layer
        // is PADDING_LEAF. All paths must still reconstruct the same root.
        let entries: Vec<_> = (1u8..=3).map(|i| entry(i, 0)).collect();
        let kt = KindTable::from_entries(entries.clone()).unwrap();
        let root = kt.root();

        for e in &entries {
            let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
            let leaf = hash_kind_table_leaf(e);
            assert_eq!(
                kp.path.root(&leaf),
                root,
                "path did not reconstruct root for {:?}",
                e.logic_ref
            );
        }
    }

    #[test]
    fn padding_sibling_for_last_entry_in_odd_table() {
        // Entries sort by (logic_ref, label_ref); entry(3,0) lands at position 2
        // (0-indexed) after sorting, which pads to position 2 in a 4-leaf layer.
        // Its sibling at depth 0 must be PADDING_LEAF.
        let entries: Vec<_> = (1u8..=3).map(|i| entry(i, 0)).collect();
        let kt = KindTable::from_entries(entries).unwrap();

        // entry(3,0) has the largest logic_ref byte, so it sorts last.
        let e = entry(3, 0);
        let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
        let (sibling, _) = kp.path.0[0];
        assert_eq!(
            sibling, PADDING_LEAF,
            "last entry in odd table must have PADDING_LEAF sibling"
        );
    }

    #[test]
    fn missing_key_returns_none() {
        let kt = KindTable::from_entries(vec![entry(1, 0), entry(2, 0)]).unwrap();
        let absent = entry(99, 0);
        assert!(kt
            .kind_path_for(&absent.logic_ref, &absent.label_ref)
            .is_none());
    }

    #[test]
    fn different_label_refs_are_distinct_keys() {
        let e1 = entry(1, 0);
        let e2 = entry(1, 1); // same logic_ref, different label_ref
        let kt = KindTable::from_entries(vec![e1.clone(), e2.clone()]).unwrap();

        assert!(kt.kind_path_for(&e1.logic_ref, &e1.label_ref).is_some());
        assert!(kt.kind_path_for(&e2.logic_ref, &e2.label_ref).is_some());

        // Looking up with the wrong label_ref must miss.
        let wrong_label = entry(1, 2);
        assert!(kt
            .kind_path_for(&wrong_label.logic_ref, &wrong_label.label_ref)
            .is_none());
    }
}
