//! Constants for compliance and padding logic proving and verification keys,
//! and the global kind-tree singleton.

use crate::{compliance::KindTreeEntry, error::ArmError, Digest};
use hex::FromHex;
use std::{path::Path, sync::OnceLock};

pub use crate::kind_tree::KindTree;

/// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
/// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");
/// Batch aggregation proving key / batch aggregation guest ELF binary
#[cfg(feature = "aggregation")]
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/batch-aggregation-guest.bin");
/// Batch aggregation (EVM ABI-encoded output) proving key / guest ELF binary
#[cfg(feature = "aggregation")]
pub const BATCH_AGGREGATION_EVM_PK: &[u8] =
    include_bytes!("../elfs/batch-aggregation-evm-guest.bin");

pub use arm_core::constants::{
    BATCH_AGGREGATION_EVM_VK, BATCH_AGGREGATION_VK, COMPLIANCE_VK, PADDING_LOGIC_VK,
};

/// Global kind tree, loaded once.
static KIND_TREE: OnceLock<KindTree> = OnceLock::new();

/// JSON-serializable representation of a kind tree entry.
/// All fields are lowercase hex strings. `kind_base` is an uncompressed
/// SEC1-encoded secp256k1 point (65 bytes = 130 hex chars).
#[derive(serde::Serialize, serde::Deserialize)]
struct KindTreeJsonEntry {
    logic_ref: String,
    label_ref: String,
    kind_base: String,
    /// Ignored by the loader; present for human readability.
    #[serde(default, rename = "_comment")]
    _comment: String,
}

/// The starter kind tree this crate ships (`data/kind_tree.json`): the
/// padding logic and the test logic, each under the zero label.
const STARTER_KIND_TREE_JSON: &str = include_str!("../data/kind_tree.json");

/// Initializes the global kind tree from a JSON file.
///
/// The file must contain a JSON array of objects with `logic_ref`, `label_ref`,
/// and `kind_base` (all lowercase hex). The kind base is stored verbatim; no
/// `hash_to_curve` is performed at load time. An optional `_comment` field is
/// accepted and ignored. Calling this a second time is a no-op; the first call wins.
pub fn init_kind_tree_from_file(path: &Path) -> Result<(), ArmError> {
    if KIND_TREE.get().is_some() {
        return Ok(());
    }
    let content = std::fs::read_to_string(path).map_err(|_| ArmError::KindTreeLoadFailed)?;
    init_kind_tree_from_entries(parse_kind_tree_json(&content)?)
}

/// Initializes the global kind tree from the starter entries this crate ships
/// (`data/kind_tree.json`), embedded at compile time, so it loads wherever
/// the crate is built. Calling this a second time is a no-op; the first call
/// wins.
pub fn init_starter_kind_tree() -> Result<(), ArmError> {
    init_kind_tree_from_entries(parse_kind_tree_json(STARTER_KIND_TREE_JSON)?)
}

/// Parses kind tree entries from the JSON format `init_kind_tree_from_file`
/// reads.
fn parse_kind_tree_json(json: &str) -> Result<Vec<KindTreeEntry>, ArmError> {
    let json_entries: Vec<KindTreeJsonEntry> =
        serde_json::from_str(json).map_err(|_| ArmError::KindTreeLoadFailed)?;
    json_entries
        .into_iter()
        .map(|e| -> Result<KindTreeEntry, ArmError> {
            let logic_ref =
                Digest::from_hex(&e.logic_ref).map_err(|_| ArmError::KindTreeLoadFailed)?;
            let label_ref =
                Digest::from_hex(&e.label_ref).map_err(|_| ArmError::KindTreeLoadFailed)?;
            let kind_base = hex::decode(&e.kind_base).map_err(|_| ArmError::KindTreeLoadFailed)?;
            Ok(KindTreeEntry {
                logic_ref,
                label_ref,
                kind_base,
            })
        })
        .collect()
}

/// Initializes the global kind tree from a pre-built list of entries.
///
/// Useful for tests or callers that construct entries programmatically.
/// Calling this a second time is a no-op; the first call wins.
pub fn init_kind_tree_from_entries(entries: Vec<KindTreeEntry>) -> Result<(), ArmError> {
    if KIND_TREE.get().is_some() {
        return Ok(());
    }
    install_kind_tree(entries)
}

fn install_kind_tree(entries: Vec<KindTreeEntry>) -> Result<(), ArmError> {
    let tree = KindTree::from_entries(entries)?;
    // First call wins; a race between two threads is benign.
    let _ = KIND_TREE.set(tree);
    Ok(())
}

/// Returns the sorted entries of the global kind tree, or an empty slice if
/// the tree has not been initialised yet.
pub fn kind_tree() -> &'static [KindTreeEntry] {
    KIND_TREE.get().map_or(&[], KindTree::entries)
}

/// Returns the global `KindTree`, or `None` if it has not been initialised.
pub fn global_kind_tree() -> Option<&'static KindTree> {
    KIND_TREE.get()
}

/// Returns the Merkle root of the global kind tree, or `None` if the tree
/// has not been initialised yet.
pub fn kind_tree_root() -> Option<Digest> {
    KIND_TREE.get().map(|t| t.root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_kind_tree_holds_the_padding_logics_kind_under_the_zero_label() {
        use crate::resource::generate_resource_kind;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use risc0_zkvm::sha::DIGEST_BYTES;

        let entries = parse_kind_tree_json(STARTER_KIND_TREE_JSON)
            .expect("the embedded starter kind tree parses");
        let zero_label = Digest::from([0u8; DIGEST_BYTES]);
        let padding = entries
            .iter()
            .find(|e| e.logic_ref == PADDING_LOGIC_VK && e.label_ref == zero_label)
            .expect("the starter kind tree has the padding logic under the zero label");
        let expected = generate_resource_kind(PADDING_LOGIC_VK, zero_label)
            .expect("the padding logic's kind")
            .to_encoded_point(false);
        assert_eq!(
            padding.kind_base,
            expected.as_bytes(),
            "the starter tree's padding kind base is not the one arm computes"
        );
        KindTree::from_entries(entries).expect("the starter kind tree is valid");
    }

    #[test]
    #[ignore = "developer utility: computes kind bases for (logic_ref, zero label_ref) pairs"]
    fn print_kind_bases_for_vks() {
        use crate::resource::generate_resource_kind;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use risc0_zkvm::sha::DIGEST_BYTES;

        let zero_label = Digest::from([0u8; DIGEST_BYTES]);
        // PADDING_LOGIC_VK comes from the const so it cannot drift from the
        // ELFs; TEST_LOGIC_VK lives in arm_test_app, which this crate cannot
        // see, so it is spelled out and must be updated with the ELFs.
        let vks = [
            ("PADDING_LOGIC_VK", PADDING_LOGIC_VK),
            (
                "TEST_LOGIC_VK",
                Digest::from(
                    <[u8; 32]>::try_from(
                        hex::decode(
                            "2f494b55a99e5bc790cc416edbfc08974b0056cfb4ab5fef3b5b49fdeec6ce3e",
                        )
                        .unwrap()
                        .as_slice(),
                    )
                    .unwrap(),
                ),
            ),
        ];
        for (name, logic_ref) in vks {
            let point = generate_resource_kind(logic_ref, zero_label).unwrap();
            let encoded = point.to_encoded_point(false);
            println!("{name}: {}", hex::encode(encoded.as_bytes()));
        }
    }

    #[test]
    #[ignore = "developer utility: mutates global KIND_TREE, run in isolation with --include-ignored"]
    fn print_kind_tree_root() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/kind_tree.json");
        init_kind_tree_from_file(&path).expect("failed to load kind tree");
        let root = kind_tree_root().expect("kind tree not initialised");
        println!("kind_tree_root: {root:?}");
        println!(
            "hex: {}",
            root.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}
