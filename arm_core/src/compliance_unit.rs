//! Compliance unit: the compliance proof paired with its serialized instance.

use serde::{Deserialize, Serialize};

/// A compliance unit consists of a compliance proof and its corresponding instance.
/// The vk is a constant in the compliance unit, so we don't place it here.
///
/// The `instance` bytes are the risc0 journal of the compliance guest;
/// decoding them into a typed [`crate::compliance::ComplianceInstance`] is a
/// host/zkVM engine operation (`anoma-rm-risc0`'s
/// `compliance_unit::get_instance`).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComplianceUnit {
    /// The serialised `InnerReceipt` for this compliance proof.
    pub proof: Vec<u8>,
    /// The serialized compliance instance.
    pub instance: Vec<u8>,
}
