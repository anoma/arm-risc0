//! Host/zkVM engine operations for logic proofs: the `LogicProver` trait,
//! proof verification, journal encode/decode, and the padding logic. The
//! wire types (`LogicVerifier`, `LogicVerifierInput`) live in
//! `anoma-rm-core` and are re-exported here unchanged.

pub use arm_core::logic_proof::*;

use crate::{
    constants::{PADDING_LOGIC_PK, PADDING_LOGIC_VK},
    error::ArmError,
    logic_instance::LogicInstance,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    proving_system::{journal_to_instance, verify as verify_proof},
    resource::Resource,
    resource_logic::TrivialLogicWitness,
    utils::words_to_bytes,
};
use rand::rngs::OsRng;
use rand::Rng;
use risc0_zkvm::{serde::to_vec, sha::Digest, InnerReceipt};
use serde::{Deserialize, Serialize};

#[cfg(feature = "prove")]
use crate::proving_system::{prove, ProofType};

/// Trait for logic provers, defining the necessary methods and associated types.
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
    #[cfg(feature = "prove")]
    fn prove(&self, proof_type: ProofType) -> Result<LogicVerifier, ArmError> {
        let (proof, instance) = prove(Self::proving_key(), self.witness(), proof_type)?;
        Ok(LogicVerifier {
            proof,
            instance,
            verifying_key: Self::verifying_key(),
        })
    }
}

/// Verifies the logic proof against the instance using its verifying key.
pub fn verify(verifier: &LogicVerifier) -> Result<(), ArmError> {
    verify_proof(&verifier.verifying_key, &verifier.instance, &verifier.proof)
        .map_err(|err| ArmError::ProofVerificationFailed(err.to_string()))
}

/// Retrieves the logic instance from the serialized instance data.
pub fn get_instance(verifier: &LogicVerifier) -> Result<LogicInstance, ArmError> {
    journal_to_instance(&verifier.instance)
}

/// Converts a `LogicVerifierInput` into a `LogicVerifier` by re-encoding
/// the reconstructed instance as a risc0 journal.
pub fn input_to_verifier(
    input: LogicVerifierInput,
    is_consumed: bool,
    root: Digest,
) -> Result<LogicVerifier, ArmError> {
    let instance_words = to_vec(&input.to_instance(is_consumed, root))
        .map_err(|_| ArmError::InstanceSerializationFailed)?;
    Ok(LogicVerifier {
        proof: input.proof,
        instance: words_to_bytes(&instance_words).to_vec(),
        verifying_key: input.verifying_key,
    })
}

/// Retrieves the inner receipt from a logic-verifier input's proof.
pub fn get_inner_receipt(input: &LogicVerifierInput) -> Result<InnerReceipt, ArmError> {
    bincode::deserialize(&input.proof).map_err(|_| ArmError::InnerReceiptDeserializationError)
}

/// Converts a `LogicVerifier` into a `LogicVerifierInput` by decoding its
/// journal for the tag and app data.
pub fn verifier_to_input(logic_proof: LogicVerifier) -> Result<LogicVerifierInput, ArmError> {
    let instance = get_instance(&logic_proof)?;
    Ok(LogicVerifierInput {
        tag: instance.tag,
        verifying_key: logic_proof.verifying_key,
        app_data: instance.app_data,
        proof: logic_proof.proof,
    })
}

/// A padding resource logic prover for generating trivial logic proofs.
#[derive(Clone, Deserialize, Serialize)]
pub struct PaddingResourceLogic {
    witness: TrivialLogicWitness,
}

impl LogicProver for PaddingResourceLogic {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Digest {
        PADDING_LOGIC_VK
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

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

impl Default for PaddingResourceLogic {
    fn default() -> Self {
        let (nf_key, nk_commitment) = crate::nullifier_key::random_pair();
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

impl LogicProver for TrivialLogicWitness {
    type Witness = TrivialLogicWitness;

    fn proving_key() -> &'static [u8] {
        PADDING_LOGIC_PK
    }

    fn verifying_key() -> Digest {
        PADDING_LOGIC_VK
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
    verify(&proof).unwrap();
}
