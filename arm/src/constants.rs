//! Constants for compliance and padding logic proving and verification keys.

use crate::{compliance::KindTableEntry, error::ArmError};
use hex::FromHex;
use risc0_zkvm::Digest;
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
static KIND_TABLE: OnceLock<(Vec<KindTableEntry>, Digest)> = OnceLock::new();

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
/// and `kind_point` (all lowercase hex). The kind point is read directly from
/// the file; no hash-to-curve is performed at load time. An optional `_comment`
/// field is accepted and ignored.
/// Calling this a second time is a no-op; the first call wins.
///
/// # Example JSON
/// ```json
/// [
///   {
///     "logic_ref": "aabbcc...",
///     "label_ref":  "ddeeff...",
///     "kind_point": "04..."
///   }
/// ]
/// ```
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
/// Useful for tests or callers that construct entries programmatically without
/// a JSON file. Calling this a second time is a no-op; the first call wins.
pub fn init_kind_table_from_entries(entries: Vec<KindTableEntry>) -> Result<(), ArmError> {
    if KIND_TABLE.get().is_some() {
        return Ok(());
    }
    install_kind_table(entries)
}

fn install_kind_table(entries: Vec<KindTableEntry>) -> Result<(), ArmError> {
    for entry in &entries {
        validate_kind_point(&entry.kind_point)?;
    }
    let hash = crate::compliance::hash_kind_table_entries(&entries);
    // First call wins; a race between two threads is benign.
    let _ = KIND_TABLE.set((entries, hash));
    Ok(())
}

/// Validates that `bytes` is a well-formed uncompressed SEC1 secp256k1 point:
/// 65 bytes, leading 0x04 byte, and on the curve.
fn validate_kind_point(bytes: &[u8]) -> Result<(), ArmError> {
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

/// Returns the currently loaded global kind table (empty slice if not yet
/// initialised).
pub fn kind_table() -> &'static [KindTableEntry] {
    KIND_TABLE.get().map_or(&[], |(entries, _)| entries)
}

/// Returns the SHA-256 commitment to the global kind table, or `None` if the
/// table has not been initialised yet.
///
/// The commitment is computed with
/// [`crate::compliance::hash_kind_table_entries`], the same algorithm the
/// compliance circuit commits with.
pub fn kind_table_hash() -> Option<&'static Digest> {
    KIND_TABLE.get().map(|(_, hash)| hash)
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
                "7421e29e44360f11f05c1c754aa47830b0363f9d1cd23d02ba9364c2b521a4e1",
            ),
            (
                "TEST_LOGIC_VK",
                "13e116647f6776a264dc2a29f044bd6e03a7c6df4d56dc9d981a2df8f3c69949",
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
    fn print_kind_table_hash() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/kind_table.json");
        init_kind_table_from_file(&path).expect("failed to load kind table");
        let hash = kind_table_hash().expect("kind table not initialised");
        println!("kind_table_hash: {hash:?}");
        println!(
            "hex: {}",
            hash.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}
