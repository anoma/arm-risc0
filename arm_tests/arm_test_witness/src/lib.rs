use anoma_rm_risc0::{
    error::ArmError,
    logic_instance::AppData,
    logic_instance::{ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    resource_logic::LogicCircuit,
    utils::bytes_to_words,
};
use anoma_rm_risc0_gadgets::{
    encryption::{Ciphertext, SecretKey},
    evm::Resource as EvmResource,
};
use k256::AffinePoint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TestLogicWitness {
    pub resource: Resource,
    pub receive_existence_path: MerklePath,
    pub is_consumed: bool,
    pub nf_key: NullifierKey,
}

impl LogicCircuit for TestLogicWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        // Load the self resource
        let tag = self.resource.tag(self.is_consumed, &self.nf_key)?;
        let root = self.receive_existence_path.root(&tag);

        // The test resource is ephemeral and has one quantity
        assert_eq!(self.resource.quantity, 1);
        assert!(self.resource.is_ephemeral);

        let resource_payload = {
            let encoded_resource = EvmResource::from(self.resource).encode();
            let encoded_resource_expirable_blob = ExpirableBlob {
                blob: bytes_to_words(&encoded_resource),
                deletion_criterion: 1,
            };
            let nk_expirable_blob = ExpirableBlob {
                blob: bytes_to_words(self.nf_key.inner()),
                deletion_criterion: 1,
            };

            vec![encoded_resource_expirable_blob, nk_expirable_blob]
        };

        let discovery_payload = {
            let cipher = Ciphertext::encrypt_with_nonce(
                &vec![0u8],
                &AffinePoint::GENERATOR,
                &SecretKey::default(),
                [0u8; 12],
            )?;
            let cipher_expirable_blob = ExpirableBlob {
                blob: cipher.as_words(),
                deletion_criterion: 1,
            };
            vec![cipher_expirable_blob]
        };

        let application_payload = {
            let application_blob = ExpirableBlob {
                blob: bytes_to_words(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]),
                deletion_criterion: 1,
            };
            vec![application_blob]
        };

        let app_data = AppData {
            resource_payload,
            discovery_payload,
            external_payload: vec![],
            application_payload,
        };

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed, // It can be either consumed or created to reduce padding resources
            root,
            app_data,
        })
    }
}

impl TestLogicWitness {
    pub fn new(
        resource: Resource,
        receive_existence_path: MerklePath,
        nf_key: NullifierKey,
        is_consumed: bool,
    ) -> Self {
        Self {
            resource,
            receive_existence_path,
            is_consumed,
            nf_key,
        }
    }
}

impl Default for TestLogicWitness {
    fn default() -> Self {
        Self {
            resource: Resource {
                quantity: 1,
                ..Default::default()
            },
            receive_existence_path: MerklePath::default(),
            is_consumed: false,
            nf_key: NullifierKey::default(),
        }
    }
}
