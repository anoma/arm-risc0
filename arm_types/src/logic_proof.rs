//! Logic proof structures and traits for proving and verifying logic statements.

use crate::{
    error::ArmError,
    logic_instance::{AppData, LogicInstance},
    utils::words_to_bytes,
};
use risc0_serde::to_vec;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// Represents a logic verifier with its proof, instance, and verifying key.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogicVerifier {
    /// The logic proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
    /// The serialized logic instance.
    pub instance: Vec<u8>,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
}

/// Inputs required to create a logic verifier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogicVerifierInputs {
    /// The tag (either commitment or nullifier) for the logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
    /// The logic proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
}

impl LogicVerifierInputs {
    /// Converts the LogicVerifierInputs into a LogicVerifier.
    pub fn to_logic_verifier(
        self,
        is_consumed: bool,
        root: Digest,
    ) -> Result<LogicVerifier, ArmError> {
        let instance_words = to_vec(&self.to_instance(is_consumed, root))
            .map_err(|_| ArmError::InstanceSerializationFailed)?;
        Ok(LogicVerifier {
            proof: self.proof,
            instance: words_to_bytes(&instance_words).to_vec(),
            verifying_key: self.verifying_key,
        })
    }

    /// Converts the LogicVerifierInputs into a LogicInstance.
    fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
    }
}
