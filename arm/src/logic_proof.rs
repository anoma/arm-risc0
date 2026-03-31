//! Logic proof structures and traits for proving and verifying logic statements.

use arm_core::logic_instance::LogicVerifierInputs;

use crate::{
    constants::{PADDING_LOGIC_PK, PADDING_LOGIC_VK},
    error::ArmError,
    logic_instance::LogicInstance,
    nullifier_key::{NullifierKey, NullifierKeyCommitment, NullifierKeyExt},
    proving_system::{journal_to_instance, verify as verify_proof},
    resource::Resource,
    resource_logic::TrivialLogicWitness,
    Digest,
};
use rand::rngs::OsRng;
use rand::Rng;
use risc0_zkvm::InnerReceipt;
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
            proof: Some(proof),
            instance,
            verifying_key: Self::verifying_key(),
        })
    }
}

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

impl LogicVerifier {
    /// Verifies the logic proof against the instance using the provided verifying key.
    pub fn verify(&self) -> Result<(), ArmError> {
        if let Some(proof) = &self.proof {
            verify_proof(&self.verifying_key, &self.instance, proof)
                .map_err(|err| ArmError::ProofVerificationFailed(err.to_string()))
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing logic proof".into(),
            ))
        }
    }

    /// Retrieves the logic instance from the serialized instance data.
    pub fn get_instance(&self) -> Result<LogicInstance, ArmError> {
        journal_to_instance(&self.instance)
    }
}

/// Extension methods on `LogicVerifierInputs` requiring risc0 serialization.
pub trait LogicVerifierInputsExt {
    /// Converts the LogicVerifierInputs into a LogicVerifier.
    fn to_logic_verifier(self, is_consumed: bool, root: Digest) -> Result<LogicVerifier, ArmError>;

    /// Retrieves the inner receipt from the logic proof.
    fn get_inner_receipt(&self) -> Result<InnerReceipt, ArmError>;
}

impl LogicVerifierInputsExt for LogicVerifierInputs {
    fn to_logic_verifier(self, is_consumed: bool, root: Digest) -> Result<LogicVerifier, ArmError> {
        let mut expected_instance = self.to_instance(is_consumed, root);
        expected_instance.compute_and_set_app_data_hash();
        let provided_instance: LogicInstance = journal_to_instance(&self.instance_journal)?;
        if provided_instance != expected_instance {
            return Err(ArmError::LogicInstanceMismatch);
        }
        Ok(LogicVerifier {
            proof: self.proof,
            instance: self.instance_journal,
            verifying_key: self.verifying_key,
        })
    }

    fn get_inner_receipt(&self) -> Result<InnerReceipt, ArmError> {
        let inner: InnerReceipt = bincode::deserialize(
            self.proof
                .as_ref()
                .ok_or(ArmError::MissingField("Missing logic proof"))?,
        )
        .map_err(|_| ArmError::InnerReceiptDeserializationError)?;
        Ok(inner)
    }
}

impl TryFrom<LogicVerifier> for LogicVerifierInputs {
    type Error = ArmError;

    fn try_from(logic_proof: LogicVerifier) -> Result<LogicVerifierInputs, Self::Error> {
        let instance = logic_proof.get_instance()?;
        Ok(LogicVerifierInputs {
            tag: instance.tag,
            verifying_key: logic_proof.verifying_key,
            app_data: instance.app_data,
            proof: logic_proof.proof,
            instance_journal: logic_proof.instance,
        })
    }
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
        *PADDING_LOGIC_VK
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

#[test]
fn test_padding_logic_prover() {
    let trivial_logic = PaddingResourceLogic::default();
    let proof = trivial_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();
}

/// Regression test: the app_data_hash must be the last 32 bytes of the journal
/// in BOTH the borsh (to_journal) and risc0 serde (env::commit) formats.
/// The on-chain PA extracts the hash via a tail slice, so this invariant is
/// security-critical.
#[test]
fn test_app_data_hash_tail_invariant_borsh_and_risc0_serde() {
    use arm_core::logic_instance::{AppData, ExpirableBlob, LogicInstance};

    // Build a non-trivial LogicInstance with actual app_data content.
    let mut app_data = AppData::new();
    app_data.add_external_payload(ExpirableBlob {
        blob: vec![0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678],
        deletion_criterion: 42,
    });
    app_data.add_resource_payload(ExpirableBlob {
        blob: vec![1, 2, 3, 4, 5],
        deletion_criterion: 0,
    });

    let mut instance = LogicInstance {
        tag: Digest::from_bytes([0x11; 32]),
        is_consumed: true,
        root: Digest::from_bytes([0x22; 32]),
        app_data,
        app_data_hash: Digest::default(),
    };
    instance.compute_and_set_app_data_hash();

    let expected_hash = instance.app_data_hash;
    assert_ne!(
        expected_hash,
        Digest::default(),
        "Hash of non-empty app_data must not be default"
    );

    // Path 1: borsh to_journal (used in tests)
    let borsh_journal = instance.to_journal().unwrap();
    assert!(borsh_journal.len() >= 32);
    assert_eq!(borsh_journal.len() % 4, 0, "Journal must be 4-byte aligned");
    let borsh_tail: [u8; 32] = borsh_journal[borsh_journal.len() - 32..]
        .try_into()
        .unwrap();
    let borsh_tail_digest = Digest::from_bytes(borsh_tail);

    // Path 2: risc0 serde (used in production by env::commit)
    let risc0_words = risc0_zkvm::serde::to_vec(&instance).expect("risc0 serde should succeed");
    let risc0_bytes: Vec<u8> = risc0_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert!(risc0_bytes.len() >= 32);
    let risc0_tail: [u8; 32] = risc0_bytes[risc0_bytes.len() - 32..].try_into().unwrap();
    let risc0_tail_digest = Digest::from_bytes(risc0_tail);

    // Both tails must equal the computed hash.
    assert_eq!(
        borsh_tail_digest, expected_hash,
        "borsh to_journal tail must contain app_data_hash"
    );
    assert_eq!(
        risc0_tail_digest, expected_hash,
        "risc0 serde tail must contain app_data_hash"
    );
}
