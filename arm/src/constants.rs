//! Constants for compliance and padding logic proving and verification keys.

use crate::{compliance::KindTableEntry, error::ArmError, resource::Resource};
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
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
        Digest::from_hex("189e18348babf7ea166d7e66e6ef047e8d71d82f119b5ebaa5a4e9ae1f0f50a4")
            .unwrap();

    /// padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("92ffaeb55bfdcea4dba72ea10aa0532beafdd34658d37173a9cf4fe34f5f0f63")
            .unwrap();
}

#[cfg(feature = "aggregation")]
lazy_static! {
    /// Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("66e657da6258e265863f716ca28bbe8b7a6f54afdadf5d2132bb422e6626f715").unwrap();
}

/// Global kind table, loaded once from a JSON file.
static GLOBAL_KIND_TABLE: OnceLock<Vec<KindTableEntry>> = OnceLock::new();

/// JSON-serializable representation of a kind table entry.
/// `logic_ref`, `label_ref`, and `kind_point` are lowercase hex strings.
#[derive(serde::Serialize, serde::Deserialize)]
struct KindTableJsonEntry {
    logic_ref: String,
    label_ref: String,
    kind_point: String,
}

/// Initializes the global kind table from a JSON file.
///
/// The file must contain a JSON array of objects with `logic_ref`, `label_ref`
/// (hex-encoded `Digest` values), and `kind_point` (hex-encoded 65-byte
/// uncompressed SEC1 point). Calling this a second time is a no-op; the first
/// call wins.
///
/// # Example JSON
/// ```json
/// [
///   {
///     "logic_ref": "aabbcc...",
///     "label_ref":  "ddeeff...",
///     "kind_point": "04aabb..."
///   }
/// ]
/// ```
pub fn init_kind_table_from_file(path: &Path) -> Result<(), ArmError> {
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
    // First call wins; subsequent calls are silently ignored.
    let _ = GLOBAL_KIND_TABLE.set(entries);
    Ok(())
}

/// Returns the currently loaded global kind table (empty slice if not yet
/// initialised).
pub fn global_kind_table() -> &'static [KindTableEntry] {
    GLOBAL_KIND_TABLE.get().map_or(&[], Vec::as_slice)
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        EncodedPoint, ProjectivePoint,
    };
    use std::path::PathBuf;

    #[test]
    fn kind_table_json_parses_and_resolves() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kind_table.json");
        init_kind_table_from_file(&path).expect("kind_table.json must parse");

        let table = global_kind_table();
        assert_eq!(table.len(), 2, "expected 2 entries");

        // Each stored point must decode back to a valid curve point.
        for entry in table {
            let encoded =
                EncodedPoint::from_bytes(&entry.kind_point).expect("kind_point must be valid SEC1");
            let point = ProjectivePoint::from_encoded_point(&encoded).into_option();
            assert!(
                point.is_some(),
                "kind_point for {:?} is not on curve",
                entry.logic_ref
            );
        }
    }

    /// Prints the uncompressed SEC1 kind point for each named resource type.
    /// Run with `cargo test print_kind_points -- --ignored --nocapture` to
    /// generate entries for `kind_table.json`.
    #[test]
    #[ignore]
    fn print_kind_points() {
        use crate::resource::Resource;
        // TEST_LOGIC_VK lives in arm_tests/arm_test_app (a separate crate) and
        // cannot be imported here; its value is referenced directly.
        // Source: arm_tests/arm_test_app/src/lib.rs — TEST_LOGIC_VK
        let test_logic_vk =
            Digest::from_hex("4dcb5900a14c792acdc5007e902e4ed9c8eccaca4865850f5b60140262a79a4a")
                .unwrap();

        let resources = [
            ("padding", *PADDING_LOGIC_VK, Digest::default()),
            ("test", test_logic_vk, Digest::default()),
        ];

        for (name, logic_ref, label_ref) in resources {
            let r = Resource {
                logic_ref,
                label_ref,
                ..Resource::default()
            };
            let point = r.kind().unwrap();
            let encoded = point.to_encoded_point(false);
            println!(
                "{name}: logic_ref={} label_ref={} kind_point={}",
                hex::encode(logic_ref.as_bytes()),
                hex::encode(label_ref.as_bytes()),
                hex::encode(encoded.as_bytes()),
            );
        }
    }
}
