use serde::{Deserialize, Serialize};

/// A compliance unit consists of a compliance proof and its instance.
///
/// The instance is stored as the raw journal bytes the compliance circuit
/// commits (see [`crate::compliance::ComplianceInstance::to_journal`]). This
/// keeps the wire format stable and avoids requiring risc0-serde to
/// deserialize — consumers that need the structured view use
/// [`crate::compliance::ComplianceInstance::from_journal`].
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComplianceUnit {
    /// The compliance proof bytes (None when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
    /// The serialized compliance instance (journal bytes).
    pub instance: Vec<u8>,
}
