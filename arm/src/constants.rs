//! Constants for compliance and padding logic proving and verification keys.

use crate::{
    compliance::KindTableEntry,
    error::ArmError,
    resource::{generate_resource_kind, Resource},
};
use hex::FromHex;
use risc0_zkvm::{
    sha::{Impl as ShaImpl, Sha256},
    Digest,
};
use std::{path::Path, sync::OnceLock};

/// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
/// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");
/// Batch aggregation proving key / batch aggregation guest ELF binary
#[cfg(feature = "aggregation")]
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/batch-aggregation-guest.bin");
/// Batch aggregation (EVM ABI-encoded output) proving key / guest ELF binary
#[cfg(all(feature = "aggregation", feature = "abi_encoding"))]
pub const BATCH_AGGREGATION_EVM_PK: &[u8] =
    include_bytes!("../elfs/batch-aggregation-evm-guest.bin");

pub use arm_core::constants::{
    BATCH_AGGREGATION_EVM_VK, BATCH_AGGREGATION_VK, COMPLIANCE_VK, PADDING_LOGIC_VK,
};

/// Global kind table and its SHA-256 commitment, loaded once from a JSON file.
static GLOBAL_KIND_TABLE: OnceLock<(Vec<KindTableEntry>, Digest)> = OnceLock::new();

/// JSON-serializable representation of a kind table entry.
/// `logic_ref` and `label_ref` are lowercase hex strings.
#[derive(serde::Serialize, serde::Deserialize)]
struct KindTableJsonEntry {
    logic_ref: String,
    label_ref: String,
}

/// Initializes the global kind table from a JSON file.
///
/// The file must contain a JSON array of objects with `logic_ref` and
/// `label_ref` (hex-encoded `Digest` values). The kind point for each entry
/// is derived via `Resource::kind()` (hash-to-curve) at load time, rather
/// than being read from the file, so the table can't drift out of sync with
/// its keys. Calling this a second time is a no-op; the first call wins.
///
/// # Example JSON
/// ```json
/// [
///   {
///     "logic_ref": "aabbcc...",
///     "label_ref":  "ddeeff..."
///   }
/// ]
/// ```
pub fn init_kind_table_from_file(path: &Path) -> Result<(), ArmError> {
    if GLOBAL_KIND_TABLE.get().is_some() {
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
            let point = generate_resource_kind(logic_ref, label_ref)
                .map_err(|_| ArmError::KindTableLoadFailed)?;
            Ok(crate::compliance::kind_table_entry(
                logic_ref, label_ref, &point,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let hash = crate::compliance::hash_kind_table_entries(&entries);
    // First call wins; a race between two threads is benign — one loses the
    // set and returns Ok(()) with whichever table was installed first.
    let _ = GLOBAL_KIND_TABLE.set((entries, hash));
    Ok(())
}

/// Returns the currently loaded global kind table (empty slice if not yet
/// initialised).
pub fn global_kind_table() -> &'static [KindTableEntry] {
    GLOBAL_KIND_TABLE.get().map_or(&[], |(entries, _)| entries)
}

/// Returns the SHA-256 commitment to the global kind table, or `None` if the
/// table has not been initialised yet.
///
/// The commitment is computed with
/// [`crate::compliance::hash_kind_table_entries`], the same algorithm the
/// compliance circuit commits with.
pub fn global_kind_table_hash() -> Option<&'static Digest> {
    GLOBAL_KIND_TABLE.get().map(|(_, hash)| hash)
}

/// Looks up `resource` in `table` and returns its pre-computed kind point, or
/// falls back to `hash_to_curve`.
pub fn kind_entry_for(table: &[KindTableEntry], resource: &Resource) -> Option<KindTableEntry> {
    table
        .iter()
        .find(|e| e.logic_ref == resource.logic_ref && e.label_ref == resource.label_ref)
        .cloned()
        .or_else(|| {
            crate::resource::kind(&resource).ok().map(|p| {
                crate::compliance::kind_table_entry(resource.logic_ref, resource.label_ref, &p)
            })
        })
}
