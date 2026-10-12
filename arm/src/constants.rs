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
    let json_entries: Vec<KindTableJsonEntry> =
        serde_json::from_str(&content).map_err(|_| ArmError::KindTableLoadFailed)?;
    let entries = json_entries
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
        .collect::<Result<Vec<_>, _>>()?;
    install_kind_table(entries)
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
                "54fccb0649c20af2d84344e48897e0d92f1d9571e41de807bf20fe81d4fdf913",
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
