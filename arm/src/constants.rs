//! Constants for compliance and padding logic proving and verification keys,
//! and the global kind-table singleton.

use crate::{compliance::KindTableEntry, error::ArmError, Digest};
use hex::FromHex;
use std::{path::Path, sync::OnceLock};

pub use crate::kind_table::KindTable;

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

/// Global kind table, loaded once.
static KIND_TABLE: OnceLock<KindTable> = OnceLock::new();

/// JSON-serializable representation of a kind table entry.
/// All fields are lowercase hex strings. `kind_point` is an uncompressed
/// SEC1-encoded secp256k1 point (65 bytes = 130 hex chars).
#[derive(serde::Serialize, serde::Deserialize)]
struct KindTableJsonEntry {
    logic_ref: String,
    label_ref: String,
    kind_point: String,
    /// Ignored by the loader; present for human readability.
    #[serde(default, rename = "_comment")]
    _comment: String,
}

/// The starter kind table this crate ships (`data/kind_table.json`): the
/// padding logic and the test logic, each under the zero label.
const STARTER_KIND_TABLE_JSON: &str = include_str!("../data/kind_table.json");

/// Initializes the global kind table from a JSON file.
///
/// The file must contain a JSON array of objects with `logic_ref`, `label_ref`,
/// and `kind_point` (all lowercase hex). The kind point is stored verbatim; no
/// `hash_to_curve` is performed at load time. An optional `_comment` field is
/// accepted and ignored. Calling this a second time is a no-op; the first call wins.
pub fn init_kind_table_from_file(path: &Path) -> Result<(), ArmError> {
    if KIND_TABLE.get().is_some() {
        return Ok(());
    }
    let content = std::fs::read_to_string(path).map_err(|_| ArmError::KindTableLoadFailed)?;
    init_kind_table_from_entries(parse_kind_table_json(&content)?)
}

/// Initializes the global kind table from the starter table this crate ships
/// (`data/kind_table.json`), embedded at compile time, so it loads wherever
/// the crate is built. Calling this a second time is a no-op; the first call
/// wins.
pub fn init_starter_kind_table() -> Result<(), ArmError> {
    init_kind_table_from_entries(parse_kind_table_json(STARTER_KIND_TABLE_JSON)?)
}

/// The entries of a kind table in the JSON format `init_kind_table_from_file`
/// reads.
fn parse_kind_table_json(json: &str) -> Result<Vec<KindTableEntry>, ArmError> {
    let json_entries: Vec<KindTableJsonEntry> =
        serde_json::from_str(json).map_err(|_| ArmError::KindTableLoadFailed)?;
    json_entries
        .into_iter()
        .map(|e| -> Result<KindTableEntry, ArmError> {
            let logic_ref =
                Digest::from_hex(&e.logic_ref).map_err(|_| ArmError::KindTableLoadFailed)?;
            let label_ref =
                Digest::from_hex(&e.label_ref).map_err(|_| ArmError::KindTableLoadFailed)?;
            let kind_point =
                hex::decode(&e.kind_point).map_err(|_| ArmError::KindTableLoadFailed)?;
            Ok(KindTableEntry {
                logic_ref,
                label_ref,
                kind_point,
            })
        })
        .collect()
}

/// Initializes the global kind table from a pre-built list of entries.
///
/// Useful for tests or callers that construct entries programmatically.
/// Calling this a second time is a no-op; the first call wins.
pub fn init_kind_table_from_entries(entries: Vec<KindTableEntry>) -> Result<(), ArmError> {
    if KIND_TABLE.get().is_some() {
        return Ok(());
    }
    install_kind_table(entries)
}

fn install_kind_table(entries: Vec<KindTableEntry>) -> Result<(), ArmError> {
    let table = KindTable::from_entries(entries)?;
    // First call wins; a race between two threads is benign.
    let _ = KIND_TABLE.set(table);
    Ok(())
}

/// Returns the sorted entries of the global kind table, or an empty slice if
/// the table has not been initialised yet.
pub fn kind_table() -> &'static [KindTableEntry] {
    KIND_TABLE.get().map_or(&[], KindTable::entries)
}

/// Returns the global `KindTable`, or `None` if it has not been initialised.
pub fn global_kind_table() -> Option<&'static KindTable> {
    KIND_TABLE.get()
}

/// Returns the Merkle root of the global kind table, or `None` if the table
/// has not been initialised yet.
pub fn kind_table_root() -> Option<Digest> {
    KIND_TABLE.get().map(|t| t.root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_kind_table_holds_the_padding_logics_kind_under_the_zero_label() {
        use crate::resource::generate_resource_kind;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use risc0_zkvm::sha::DIGEST_BYTES;

        let entries = parse_kind_table_json(STARTER_KIND_TABLE_JSON)
            .expect("the embedded starter kind table parses");
        let zero_label = Digest::from([0u8; DIGEST_BYTES]);
        let padding = entries
            .iter()
            .find(|e| e.logic_ref == PADDING_LOGIC_VK && e.label_ref == zero_label)
            .expect("the starter kind table has the padding logic under the zero label");
        let expected = generate_resource_kind(PADDING_LOGIC_VK, zero_label)
            .expect("the padding logic's kind")
            .to_encoded_point(false);
        assert_eq!(
            padding.kind_point,
            expected.as_bytes(),
            "the starter table's padding kind point is not the one arm computes"
        );
        KindTable::from_entries(entries).expect("the starter kind table is a valid table");
    }

    #[test]
    #[ignore = "developer utility: computes kind points for (logic_ref, zero label_ref) pairs"]
    fn print_kind_points_for_vks() {
        use crate::resource::generate_resource_kind;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use risc0_zkvm::sha::DIGEST_BYTES;

        let zero_label = Digest::from([0u8; DIGEST_BYTES]);
        let vks = [
            (
                "PADDING_LOGIC_VK",
                "2ba12576f5caf1149c18fe98b35c56adecc9ffaf39eafef49ea050e38d04d012",
            ),
            (
                "TEST_LOGIC_VK",
                "1e8deddc609266fc28d50dd33aca7c32dd3257df20b63becf3d0af099c6cb95d",
            ),
        ];
        for (name, hex_vk) in vks {
            let bytes: [u8; 32] = hex::decode(hex_vk).unwrap().try_into().unwrap();
            let logic_ref = Digest::from(bytes);
            let point = generate_resource_kind(logic_ref, zero_label).unwrap();
            let encoded = point.to_encoded_point(false);
            println!("{name}: {}", hex::encode(encoded.as_bytes()));
        }
    }

    #[test]
    #[ignore = "developer utility: mutates global KIND_TABLE, run in isolation with --include-ignored"]
    fn print_kind_table_root() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/kind_table.json");
        init_kind_table_from_file(&path).expect("failed to load kind table");
        let root = kind_table_root().expect("kind table not initialised");
        println!("kind_table_root: {root:?}");
        println!(
            "hex: {}",
            root.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}
