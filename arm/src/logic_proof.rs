use crate::{
    constants::{PADDING_LOGIC_PK, PADDING_LOGIC_VK},
    error::ArmError,
    logic_instance::AppData,
    logic_instance::LogicInstance,
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    proving_system::{journal_to_instance, verify as verify_proof},
    resource::Resource,
    resource_logic::TrivialLogicWitness,
    utils::words_to_bytes,
};
use rand::Rng;
use risc0_zkvm::{serde::to_vec, sha::Digest};
use serde::{Deserialize, Serialize};

#[cfg(feature = "prove")]
use crate::proving_system::prove;

pub trait LogicProver: Default + Clone + Serialize + for<'de> Deserialize<'de> {
    type Witness: Default + Clone + Serialize + for<'de> Deserialize<'de>;

    fn proving_key() -> &'static [u8];

    fn verifying_key() -> Digest;

    fn verifying_key_as_bytes() -> Vec<u8> {
        Self::verifying_key().as_bytes().to_vec()
    }

    fn witness(&self) -> &Self::Witness;

    #[cfg(feature = "prove")]
    fn prove(&self) -> Result<LogicVerifier, ArmError> {
        let (proof, instance) = prove(Self::proving_key(), self.witness())?;
        Ok(LogicVerifier {
            proof: Some(proof),
            instance,
            verifying_key: Self::verifying_key(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogicVerifier {
    pub proof: Option<Vec<u8>>,
    pub instance: Vec<u8>,
    pub verifying_key: Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogicVerifierInputs {
    pub tag: Digest,
    pub verifying_key: Digest,
    pub app_data: AppData,
    pub proof: Option<Vec<u8>>,
}

impl LogicVerifier {
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

    pub fn get_instance(&self) -> Result<LogicInstance, ArmError> {
        journal_to_instance(&self.instance)
    }
}

impl LogicVerifierInputs {
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

    fn to_instance(&self, is_consumed: bool, root: Digest) -> LogicInstance {
        LogicInstance {
            tag: self.tag,
            is_consumed,
            root,
            app_data: self.app_data.clone(),
        }
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
        })
    }
}

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
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        let witness = TrivialLogicWitness {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        };
        PaddingResourceLogic { witness }
    }
    pub fn create_padding_resource(nk_commitment: NullifierKeyCommitment) -> Resource {
        let mut rng = rand::thread_rng();
        Resource {
            logic_ref: Self::verifying_key(),
            label_ref: Digest::default(),
            quantity: 0,
            value_ref: Digest::default(),
            is_ephemeral: true,
            nonce: rng.gen(),
            nk_commitment,
            rand_seed: rng.gen(),
        }
    }
}

impl Default for PaddingResourceLogic {
    fn default() -> Self {
        let (nf_key, nk_commitment) = NullifierKey::random_pair();
        let resource = Self::create_padding_resource(nk_commitment);
        let receive_existence_path =
            MerklePath::from_path(vec![(Digest::default(), false); 3].as_slice());
        let witness = TrivialLogicWitness {
            resource,
            receive_existence_path,
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
    let proof = trivial_logic.prove().unwrap();
    proof.verify().unwrap();
}
