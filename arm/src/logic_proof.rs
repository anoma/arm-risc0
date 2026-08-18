//! Logic proof structures and traits for proving and verifying logic statements.

use crate::logic_instance::AppData;
#[cfg(feature = "transaction")]
use crate::nullifier_key::NullifierKey;
#[cfg(feature = "transaction")]
use crate::resource::Resource;
use crate::resource_logic::TrivialLogicWitness;
#[cfg(feature = "transaction")]
use crate::{
    constants::{PADDING_LOGIC_PK, PADDING_LOGIC_VK},
    error::ArmError,
    logic_instance::LogicInstance,
    nullifier_key::NullifierKeyCommitment,
    proving_system::{journal_to_instance, verify as verify_proof},
    utils::words_to_bytes,
};
#[cfg(feature = "transaction")]
use rand::rngs::OsRng;
#[cfg(feature = "transaction")]
use rand::Rng;
use risc0_zkp::core::digest::Digest;
#[cfg(feature = "transaction")]
use risc0_zkvm::{serde::to_vec, InnerReceipt};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "prove", feature = "transaction"))]
use crate::proving_system::{prove, ProofType};

/// Trait for logic provers, defining the necessary methods and associated types.
#[cfg(feature = "transaction")]
pub trait LogicProver: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    /// The type of witness used for proving.
    type Witness: Default + Clone + Serialize + for<'de> Deserialize<'de>;

    /// Returns the proving key for the logic prover.
    fn proving_key() -> &'static [u8];

    /// Returns the verifying key for the logic prover.
    fn verifying_key() -> Digest;

    /// Returns the verifying key as bytes.
    fn verifying_key_as_bytes() -> Vec<u8> {
        Self::verifying_key().as_bytes().to_vec()
    }

    /// Returns a reference to the witness.
    fn witness(&self) -> &Self::Witness;

    /// Proves the logic statement using the provided witness and proof type.
    #[cfg(all(feature = "prove", feature = "transaction"))]
    fn prove(&self, proof_type: ProofType) -> Result<LogicVerifier, ArmError> {
        let (proof, instance) = prove(Self::proving_key(), self.witness(), proof_type)?;
        Ok(LogicVerifier {
            proof,
            instance,
            verifying_key: Self::verifying_key(),
        })
    }
}

/// Represents a logic verifier with its proof, instance, and verifying key.
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

#[cfg(feature = "transaction")]
impl LogicVerifier {
    /// Verifies the logic proof against the instance using the provided verifying key.
    pub fn verify(&self) -> Result<(), ArmError> {
        verify_proof(&self.verifying_key, &self.instance, &self.proof)
            .map_err(|err| ArmError::ProofVerificationFailed(err.to_string()))
    }

    /// Retrieves the logic instance from the serialized instance data.
    pub fn get_instance(&self) -> Result<LogicInstance, ArmError> {
        journal_to_instance(&self.instance)
    }
}

#[cfg(feature = "transaction")]
impl LogicVerifierInput {
    /// Converts the LogicVerifierInput into a LogicVerifier.
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

    /// Converts the LogicVerifierInput into a LogicInstance.
    fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
    }

    /// Retrieves the inner receipt from the logic proof.
    pub fn get_inner_receipt(&self) -> Result<InnerReceipt, ArmError> {
        bincode::deserialize(&self.proof).map_err(|_| ArmError::InnerReceiptDeserializationError)
    }
}

#[cfg(feature = "transaction")]
impl TryFrom<LogicVerifier> for LogicVerifierInput {
    type Error = ArmError;

    fn try_from(logic_proof: LogicVerifier) -> Result<LogicVerifierInput, Self::Error> {
        let instance = logic_proof.get_instance()?;
        Ok(LogicVerifierInput {
            tag: instance.tag,
            verifying_key: logic_proof.verifying_key,
            app_data: instance.app_data,
            proof: logic_proof.proof,
        })
    }
}

/// A padding resource logic prover for generating trivial logic proofs.
#[derive(Clone, Deserialize, Serialize)]
pub struct PaddingResourceLogic {
    witness: TrivialLogicWitness,
}

#[cfg(feature = "transaction")]
impl LogicProver for PaddingResourceLogic {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Digest {
        *PADDING_LOGIC_VK
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

#[cfg(feature = "transaction")]
impl PaddingResourceLogic {
    /// Creates a new PaddingResourceLogic with the given parameters.
    pub fn new(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        let witness = TrivialLogicWitness {
            resource,
            action_tree_root,
            is_consumed,
            nf_key,
        };
        PaddingResourceLogic { witness }
    }

    /// Creates a padding resource with the given nullifier key commitment.
    pub fn create_padding_resource(nk_commitment: NullifierKeyCommitment) -> Resource {
        Resource {
            logic_ref: Self::verifying_key(),
            label_ref: Digest::default(),
            quantity: 0,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce: OsRng.gen(),
            nk_commitment,
            rand_seed: OsRng.gen(),
        }
    }
}

#[cfg(feature = "transaction")]
impl Default for PaddingResourceLogic {
    fn default() -> Self {
        let (nf_key, nk_commitment) = NullifierKey::random_pair();
        let resource = Self::create_padding_resource(nk_commitment);
        let witness = TrivialLogicWitness {
            resource,
            action_tree_root: Digest::default(),
            is_consumed: false,
            nf_key,
        };
        PaddingResourceLogic { witness }
    }
}

#[cfg(feature = "transaction")]
impl LogicProver for TrivialLogicWitness {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Digest {
        *PADDING_LOGIC_VK
    }

    fn witness(&self) -> &Self::Witness {
        self
    }
}

#[cfg(all(test, feature = "prove"))]
#[test]
fn test_padding_logic_prover() {
    let trivial_logic = PaddingResourceLogic::default();
    let proof = trivial_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();
}
