//! Constants for compliance and padding logic proving and verification keys.

use crate::{
    compliance::KindTableEntry,
    error::ArmError,
    resource::{generate_resource_kind, Resource},
};
use hex::FromHex;
use lazy_static::lazy_static;
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

lazy_static! {
    /// compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("88df64fe233c97307dd518c1757bf6cfca1f17f7103b4069dd9e2848db9d8434")
            .unwrap();

    /// padding logic verification key / padding image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("4527548f4dd31781b4bf48eb0c72869a9a9375728e064ddcdce5381c947fea8f")
            .unwrap();
}

#[cfg(feature = "aggregation")]
lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("5dc2615f3d14a517a25aadfe53a882394e602740514574f3201bbe735269058e").unwrap();
}

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
            Ok(KindTableEntry::new(logic_ref, label_ref, &point))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let hash = hash_kind_table_entries(&entries);
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
/// The commitment is computed using the same algorithm as
/// `ComplianceWitness::hash_kind_table`: SHA-256 over the concatenated
/// `(logic_ref ‖ label_ref ‖ kind_point)` bytes of every entry in order.
pub fn global_kind_table_hash() -> Option<&'static Digest> {
    GLOBAL_KIND_TABLE.get().map(|(_, hash)| hash)
}

fn hash_kind_table_entries(entries: &[KindTableEntry]) -> Digest {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(entry.logic_ref.as_bytes());
        bytes.extend_from_slice(entry.label_ref.as_bytes());
        bytes.extend_from_slice(&entry.kind_point);
    }
    *ShaImpl::hash_bytes(&bytes)
}

/// Looks up `resource` in `table` and returns its pre-computed kind point, or
/// falls back to `hash_to_curve`.
pub fn kind_entry_for(table: &[KindTableEntry], resource: &Resource) -> Option<KindTableEntry> {
    table
        .iter()
        .find(|e| e.logic_ref == resource.logic_ref && e.label_ref == resource.label_ref)
        .cloned()
        .or_else(|| {
            resource
                .kind()
                .ok()
                .map(|p| KindTableEntry::new(resource.logic_ref, resource.label_ref, &p))
        })
}
