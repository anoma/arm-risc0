//! `KindTree`: a Merkle tree over pre-computed kind bases for known resource
//! types, used to skip `hash_to_curve` inside the compliance circuit.

use crate::{
    compliance::{hash_kind_tree_leaf, KindPath, KindTreeEntry},
    error::ArmError,
    resource::ResourceWitness,
    Digest,
};
use merkle_layers::MerkleLayers;

/// The kind tree: a fixed binary Merkle tree over known `(logic_ref,
/// label_ref)` → kind-base mappings that lets a compliance witness skip
/// `hash_to_curve` for well-known resource types.
///
/// **Tree construction** — entries are sorted lexicographically by
/// `(logic_ref, label_ref)` bytes so that host-side path computation is
/// deterministic regardless of insertion order. Duplicate `(logic_ref,
/// label_ref)` pairs are rejected. Leaf `i` is
/// `hash_kind_tree_leaf(&entries[i])`. The leaf layer is padded to the next
/// power of two with `PADDING_LEAF`; internal nodes are `hash_two(left,
/// right)`. An empty tree has root `PADDING_LEAF`.
///
/// **In-circuit verification** — `constrain()` derives the committed
/// `kind_tree_root` from the paths supplied in `ComplianceWitness.kind_paths`:
/// each non-`None` path must produce the same root via `MerklePath::root(leaf)`,
/// and the prover has no freedom to choose a different root.
pub struct KindTree {
    entries: Vec<KindTreeEntry>,
    /// The tree over `hash_kind_tree_leaf` of each entry, in the order of `entries`.
    layers: MerkleLayers,
}

impl KindTree {
    /// Returns a `KindTree` with no entries. All resources fall back to
    /// `hash_to_curve`; the committed root is `PADDING_LEAF`.
    pub fn empty() -> KindTree {
        KindTree {
            entries: Vec::new(),
            layers: MerkleLayers::new(std::iter::empty()),
        }
    }

    /// Builds a `KindTree` from a list of entries, validating every kind
    /// base, rejecting duplicates, and sorting by `(logic_ref, label_ref)`.
    /// A rejection names the position of the offending kind base, or the
    /// `(logic_ref, label_ref)` pair that appears twice.
    pub fn from_entries(mut entries: Vec<KindTreeEntry>) -> Result<KindTree, ArmError> {
        for (position, entry) in entries.iter().enumerate() {
            validate_kind_base(&entry.kind_base, position)?;
        }
        entries.sort_by(|a, b| entry_key(a).cmp(&entry_key(b)));
        if let Some(w) = entries
            .windows(2)
            .find(|w| w[0].logic_ref == w[1].logic_ref && w[0].label_ref == w[1].label_ref)
        {
            return Err(ArmError::DuplicateKindTreeEntry {
                logic_ref: w[0].logic_ref,
                label_ref: w[0].label_ref,
            });
        }
        let layers = MerkleLayers::new(entries.iter().map(hash_kind_tree_leaf));
        Ok(KindTree { entries, layers })
    }

    /// The Merkle root of the tree. A compliance unit that uses a kind path commits it as
    /// `ComplianceInstance.kind_tree_root`; a unit without kind paths commits `PADDING_LEAF`.
    pub fn root(&self) -> Digest {
        self.layers.root()
    }

    /// The sorted entries.
    pub fn entries(&self) -> &[KindTreeEntry] {
        &self.entries
    }

    /// Returns the `KindPath` for `(logic_ref, label_ref)`, or `None` if the
    /// pair is not in the tree.
    pub fn kind_path_for(&self, logic_ref: &Digest, label_ref: &Digest) -> Option<KindPath> {
        let key = (logic_ref.as_bytes(), label_ref.as_bytes());
        let pos = self
            .entries
            .binary_search_by(|e| entry_key(e).cmp(&key))
            .ok()?;
        Some(KindPath {
            kind_base: self.entries[pos].kind_base.clone(),
            path: self.layers.path(pos)?,
        })
    }

    /// Returns one `Option<KindPath>` per resource, in the order of
    /// `resources`, matching the indexing `constrain()` expects in
    /// `ComplianceWitness.kind_paths`.
    pub fn kind_paths_for(&self, resources: &[ResourceWitness]) -> Vec<Option<KindPath>> {
        resources
            .iter()
            .map(|r| self.kind_path_for(&r.resource().logic_ref, &r.resource().label_ref))
            .collect()
    }
}

/// Sort and search key for an entry: `(logic_ref, label_ref)` byte slices.
/// Both `from_entries` (sort) and `kind_path_for` (binary search) use it so
/// they always agree on the ordering.
fn entry_key(entry: &KindTreeEntry) -> (&[u8], &[u8]) {
    (entry.logic_ref.as_bytes(), entry.label_ref.as_bytes())
}

/// Validates that `bytes` is a well-formed uncompressed SEC1 secp256k1 point:
/// 65 bytes, leading 0x04 byte, and on the curve.
pub(crate) fn validate_kind_base(bytes: &[u8], position: usize) -> Result<(), ArmError> {
    crate::resource::decode_kind_base(bytes, position).map(|_| ())
}

/// A binary Merkle tree built once and stored as its layers, so paths can be
/// read in O(log n) without rebuilding the tree per lookup.
mod merkle_layers {
    use arm_core::merkle_path::{MerklePath, PADDING_LEAF};
    use arm_core::utils::hash_two;

    use crate::Digest;

    pub(super) struct MerkleLayers {
        /// Layers from the (padded) leaf layer up to, but not including, the root.
        below_root: Vec<Vec<Digest>>,
        root: Digest,
    }

    impl MerkleLayers {
        /// Builds every layer over `leaves`. With no leaves the root is `PADDING_LEAF`.
        pub(super) fn new(leaves: impl ExactSizeIterator<Item = Digest>) -> Self {
            let width = leaves.len().next_power_of_two();
            let mut layer: Vec<Digest> = Vec::with_capacity(width);
            layer.extend(leaves);
            layer.resize(width, PADDING_LEAF);

            let depth = width.ilog2() as usize;
            let mut below_root = Vec::with_capacity(depth);
            for _ in 0..depth {
                let parent = parent_layer(&layer);
                below_root.push(layer);
                layer = parent;
            }
            MerkleLayers {
                below_root,
                root: layer[0],
            }
        }

        pub(super) fn root(&self) -> Digest {
            self.root
        }

        /// The Merkle path of the leaf at `index`, or `None` if `index` is
        /// outside the leaf layer. Each entry holds the sibling of the node on
        /// the path and whether that node is the right child, as
        /// `MerklePath::root()` expects.
        pub(super) fn path(&self, index: usize) -> Option<MerklePath> {
            // A one-leaf tree has no layer below the root: the leaf is the root.
            let leaf_count = self.below_root.first().map_or(1, Vec::len);
            if index >= leaf_count {
                return None;
            }
            let siblings: Vec<(Digest, bool)> = self
                .below_root
                .iter()
                .enumerate()
                .map(|(level, layer)| {
                    let node = index >> level;
                    let is_right_child = node % 2 == 1;
                    let sibling = if is_right_child { node - 1 } else { node + 1 };
                    (layer[sibling], is_right_child)
                })
                .collect();
            Some(MerklePath::from_path(&siblings))
        }
    }

    /// Hashes each pair of neighbouring nodes into their parent.
    fn parent_layer(layer: &[Digest]) -> Vec<Digest> {
        layer.chunks(2).map(|c| hash_two(&c[0], &c[1])).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::hash_kind_tree_leaf;
    use arm_core::merkle_path::PADDING_LEAF;

    /// A valid uncompressed secp256k1 generator point (G), used as a
    /// stand-in kind base in unit tests. 65 bytes, leading 0x04.
    fn generator_point() -> Vec<u8> {
        hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .unwrap()
    }

    fn entry(logic_byte: u8, label_byte: u8) -> KindTreeEntry {
        let mut logic = [0u8; 32];
        logic[31] = logic_byte;
        let mut label = [0u8; 32];
        label[31] = label_byte;
        KindTreeEntry {
            logic_ref: Digest::from(logic),
            label_ref: Digest::from(label),
            kind_base: generator_point(),
        }
    }

    // ── construction ──────────────────────────────────────────────────────────

    #[test]
    fn empty_tree_has_padding_leaf_root() {
        assert_eq!(KindTree::empty().root(), PADDING_LEAF);
    }

    #[test]
    fn single_entry_root_equals_its_leaf_hash() {
        let e = entry(1, 0);
        let leaf = hash_kind_tree_leaf(&e);
        let kt = KindTree::from_entries(vec![e]).unwrap();
        // next_power_of_two(1) == 1: the layer is already width-1, so no
        // padding occurs and the root is the leaf itself.
        assert_eq!(kt.root(), leaf);
    }

    #[test]
    fn rejects_invalid_kind_base() {
        let mut e = entry(1, 0);
        // 65 bytes, but no 0x04 prefix: it fails the encoding check before
        // the curve check is reached.
        e.kind_base = vec![0u8; 65];
        assert_eq!(
            KindTree::from_entries(vec![e]).err(),
            Some(ArmError::InvalidKindBaseEncoding { position: 0 })
        );

        // A well-formed uncompressed encoding whose coordinates are not on
        // the curve reaches, and fails, the curve check.
        let mut off_curve = entry(1, 0);
        off_curve.kind_base = {
            let mut b = vec![0u8; 65];
            b[0] = 0x04;
            b
        };
        assert_eq!(
            KindTree::from_entries(vec![off_curve]).err(),
            Some(ArmError::KindBaseNotOnCurve { position: 0 })
        );
    }

    #[test]
    fn rejects_duplicate_logic_label_pair() {
        let entries = vec![entry(1, 0), entry(1, 0)];
        let e = entry(1, 0);
        assert_eq!(
            KindTree::from_entries(entries).err(),
            Some(ArmError::DuplicateKindTreeEntry {
                logic_ref: e.logic_ref,
                label_ref: e.label_ref,
            }),
            "duplicate (logic_ref, label_ref) must be rejected"
        );
    }

    #[test]
    fn insertion_order_does_not_affect_root() {
        let e1 = entry(1, 0);
        let e2 = entry(2, 0);
        let e3 = entry(3, 0);

        let kt_abc = KindTree::from_entries(vec![e1.clone(), e2.clone(), e3.clone()]).unwrap();
        let kt_cba = KindTree::from_entries(vec![e3.clone(), e2.clone(), e1.clone()]).unwrap();
        let kt_bca = KindTree::from_entries(vec![e2.clone(), e3.clone(), e1.clone()]).unwrap();

        assert_eq!(kt_abc.root(), kt_cba.root());
        assert_eq!(kt_abc.root(), kt_bca.root());
    }

    // ── path generation ───────────────────────────────────────────────────────

    #[test]
    fn all_paths_reconstruct_root_power_of_two() {
        // Four entries — exact power of two, no padding needed at the leaf layer.
        let entries: Vec<_> = (1u8..=4).map(|i| entry(i, 0)).collect();
        let kt = KindTree::from_entries(entries.clone()).unwrap();
        let root = kt.root();

        for e in &entries {
            let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
            let leaf = hash_kind_tree_leaf(e);
            assert_eq!(kp.path.root(&leaf), root, "path did not reconstruct root");
        }
    }

    #[test]
    fn all_paths_reconstruct_root_non_power_of_two() {
        // Three entries pad to four; last entry's sibling at the bottom layer
        // is PADDING_LEAF. All paths must still reconstruct the same root.
        let entries: Vec<_> = (1u8..=3).map(|i| entry(i, 0)).collect();
        let kt = KindTree::from_entries(entries.clone()).unwrap();
        let root = kt.root();

        for e in &entries {
            let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
            let leaf = hash_kind_tree_leaf(e);
            assert_eq!(
                kp.path.root(&leaf),
                root,
                "path did not reconstruct root for {:?}",
                e.logic_ref
            );
        }
    }

    #[test]
    fn padding_sibling_for_last_entry_in_odd_tree() {
        // Entries sort by (logic_ref, label_ref); entry(3,0) lands at position 2
        // (0-indexed) after sorting, which pads to position 2 in a 4-leaf layer.
        // Its sibling at depth 0 must be PADDING_LEAF.
        let entries: Vec<_> = (1u8..=3).map(|i| entry(i, 0)).collect();
        let kt = KindTree::from_entries(entries).unwrap();

        // entry(3,0) has the largest logic_ref byte, so it sorts last.
        let e = entry(3, 0);
        let kp = kt.kind_path_for(&e.logic_ref, &e.label_ref).unwrap();
        let (sibling, _) = kp.path.0[0];
        assert_eq!(
            sibling, PADDING_LEAF,
            "last entry in odd tree must have PADDING_LEAF sibling"
        );
    }

    #[test]
    fn missing_key_returns_none() {
        let kt = KindTree::from_entries(vec![entry(1, 0), entry(2, 0)]).unwrap();
        let absent = entry(99, 0);
        assert!(kt
            .kind_path_for(&absent.logic_ref, &absent.label_ref)
            .is_none());
    }

    #[test]
    fn different_label_refs_are_distinct_keys() {
        let e1 = entry(1, 0);
        let e2 = entry(1, 1); // same logic_ref, different label_ref
        let kt = KindTree::from_entries(vec![e1.clone(), e2.clone()]).unwrap();

        assert!(kt.kind_path_for(&e1.logic_ref, &e1.label_ref).is_some());
        assert!(kt.kind_path_for(&e2.logic_ref, &e2.label_ref).is_some());

        // Looking up with the wrong label_ref must miss.
        let wrong_label = entry(1, 2);
        assert!(kt
            .kind_path_for(&wrong_label.logic_ref, &wrong_label.label_ref)
            .is_none());
    }
}
