//! Logic proof wire types.

use crate::logic_instance::{AppData, LogicInstance};
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// Represents a logic verifier with its proof, instance, and verifying key.
///
/// The `instance` bytes are the risc0 journal of the logic guest; decoding
/// or (re-)encoding journals is a host/zkVM engine operation
/// (`anoma-rm-risc0`'s `logic_proof` module).
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogicVerifier {
    /// The serialised `InnerReceipt` for this logic proof.
    pub proof: Vec<u8>,
    /// The serialized logic instance.
    pub instance: Vec<u8>,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
}

/// Inputs required to create a logic verifier.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogicVerifierInput {
    /// The tag (either commitment or nullifier) for the logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
    /// The serialised `InnerReceipt` for this logic proof.
    pub proof: Vec<u8>,
}

impl LogicVerifierInput {
    /// Reconstructs the logic instance this input's proof commits to, given
    /// the two pieces of context the input does not carry.
    pub fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
    }
}
