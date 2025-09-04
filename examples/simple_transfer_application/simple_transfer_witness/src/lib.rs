use std::vec;

pub use arm::resource_logic::LogicCircuit;
use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{AffinePoint, Ciphertext, SecretKey},
    evm::{ERC20Call, ForwarderCalldata, Resource as EvmResource},
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, hash_bytes, words_to_bytes},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SimpleTransferWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub existence_path: MerklePath,
    // A consumed resource requires a nullifier key
    pub nf_key: Option<NullifierKey>,
    // The authorization verifying key corresponds to the resource.value.owner
    pub auth_pk: Option<AuthorizationVerifyingKey>,
    // A consumed persistent resource requires an authorization signature
    pub auth_sig: Option<AuthorizationSignature>,
    // TODO: A permit2 signature is verified in PA for minting
    pub forwarder_sig: Option<Vec<u8>>,
    // Obtain from the receiver for discovery_payload
    pub discovery_pk: AffinePoint,
    // randomly generated for discovery_payload
    pub discovery_sk: SecretKey,
    // randomly generated for discovery_payload
    pub discovery_nonce: [u8; 12],
    // Obtain from the receiver for persistent resource_ciphertext
    pub encryption_pk: Option<AffinePoint>,
    // randomly generated for persistent resource_ciphertext
    pub encryption_sk: Option<SecretKey>,
    // randomly generated for persistent resource_ciphertext
    pub encryption_nonce: Option<[u8; 12]>,
    // forwarder address(32bytes) in externalPayload used for erc20 call
    pub forwarder_addr: Option<Vec<u8>>,
    // erc20 address in externalPayload used for erc20 call
    pub erc20_addr: Option<Vec<u8>>,
    // user address in externalPayload used for erc20 call
    pub user_addr: Option<Vec<u8>>,
}

impl LogicCircuit for SimpleTransferWitness {
    // label = sha2(forwarderAddress, erc20addr)
    // userAddr is from witnesses

    // IF r.isConsumed  AND r.isEphemeral
    //  self.quantity = externalPayload.lockedQuantity
    //  self.label.forwarderAddress = externalPayload.untrustedForwarder
    //  self.label.erc20addr = externalPayload.erc20Addr
    //  externalPayload.userAddr is from witness
    //  verify(applicationPayload.S, abi.encodePacked(actionTreeRoot, externalPayload[0].blob), externalPayload.senderKey) = true
    // IF r.isConsumed = false AND r.isEphemeral
    //  r.label.forwarderAddress = externalPayload.untrustedForwarder
    //  r.quantity = externalPayload.amount
    //  self.label.erc20addr = externalPayload.erc20Addr
    //  r.value = externalPayload.userAddr
    // IF r.isConsumed AND r.isEphemeral = false
    //  verify(applicationPayload.S, actionTreeRoot, r.value.owner) = true
    //  externalPayload.is_empty()
    // IF r.isConsumed = false AND r.isEphemeral = false
    //  externalPayload.is_empty()

    fn constrain(&self) -> LogicInstance {
        // Load resources
        let cm = self.resource.commitment();
        let tag = if self.is_consumed {
            self.resource
                .nullifier_from_commitment(self.nf_key.as_ref().unwrap(), &cm)
                .unwrap()
        } else {
            cm
        };

        // Check the existence path
        let root = self.existence_path.root(&tag);

        // Generate discovery_payload
        let discovery_payload = {
            let cipher = Ciphertext::encrypt(
                &vec![0u8],
                &self.discovery_pk,
                &self.discovery_sk,
                self.discovery_nonce,
            );
            let cipher_expirable_blob = ExpirableBlob {
                blob: cipher.as_words(),
                deletion_criterion: 1,
            };
            vec![cipher_expirable_blob]
        };

        // Generate external_payload and application_payload
        let (resource_payload, external_payload, application_payload) =
            if self.resource.is_ephemeral {
                // Generate resource_payload
                let resource_payload = {
                    let encoded_resource = EvmResource::from(self.resource.clone()).encode();
                    let encoded_resource_expirable_blob = ExpirableBlob {
                        blob: bytes_to_words(&encoded_resource),
                        deletion_criterion: 1,
                    };
                    let nk_expirable_blob = ExpirableBlob {
                        blob: bytes_to_words(self.nf_key.as_ref().unwrap().inner()),
                        deletion_criterion: 1,
                    };

                    vec![encoded_resource_expirable_blob, nk_expirable_blob]
                };

                // Check resource label: label = sha2(forwarder_addr, erc20_addr)
                let forwarder_addr = self.forwarder_addr.as_ref().unwrap();
                let erc20_addr = self.erc20_addr.as_ref().unwrap();
                let user_addr = self.user_addr.as_ref().unwrap();
                let mut label_data = vec![];
                label_data.extend_from_slice(forwarder_addr);
                label_data.extend_from_slice(erc20_addr);
                assert_eq!(self.resource.label_ref, hash_bytes(&label_data));

                let (external_payload, application_payload) = if self.is_consumed {
                    // Minting
                    let erc20_call_data =
                        ERC20Call::from_bytes(self.resource.quantity, erc20_addr, user_addr, true);
                    let forwarder_call_data = ForwarderCalldata::from_bytes(
                        forwarder_addr,
                        erc20_call_data.encode(),
                        vec![0u8],
                    );
                    let external_payload = {
                        let call_data_expirable_blob = ExpirableBlob {
                            blob: bytes_to_words(&forwarder_call_data.encode()),
                            deletion_criterion: 1,
                        };
                        vec![call_data_expirable_blob]
                    };

                    let application_payload = {
                        let sig_expirable_blob = ExpirableBlob {
                            blob: bytes_to_words(self.forwarder_sig.as_ref().unwrap()),
                            deletion_criterion: 1,
                        };
                        vec![sig_expirable_blob]
                    };
                    (external_payload, application_payload)
                } else {
                    // Burning
                    let erc20_call_data = ERC20Call::from_bytes(
                        self.resource.quantity,
                        erc20_addr,
                        &self.resource.value_ref, // from resource value for burning
                        false,
                    );
                    let forwarder_call_data = ForwarderCalldata::from_bytes(
                        forwarder_addr,
                        erc20_call_data.encode(),
                        vec![0u8],
                    );
                    let external_payload = {
                        let call_data_expirable_blob = ExpirableBlob {
                            blob: bytes_to_words(&forwarder_call_data.encode()),
                            deletion_criterion: 1,
                        };
                        vec![call_data_expirable_blob]
                    };
                    (external_payload, vec![])
                };

                (resource_payload, external_payload, application_payload)
            } else {
                // Generate resource ciphertext
                // TODO: figure out where to place the ciphertext
                let resource_ciphertext = {
                    let cipher = Ciphertext::encrypt(
                        &self.resource.to_bytes(),
                        &self.encryption_pk.unwrap(),
                        self.encryption_sk.as_ref().unwrap(),
                        self.encryption_nonce.unwrap(),
                    );
                    let cipher_expirable_blob = ExpirableBlob {
                        blob: cipher.as_words(),
                        deletion_criterion: 1,
                    };
                    vec![cipher_expirable_blob]
                };

                // Consume a persistent resource
                if self.is_consumed {
                    // check value
                    assert_eq!(
                        self.resource.value_ref,
                        hash_bytes(&self.auth_pk.unwrap().to_bytes())
                    );
                    // Verify the authorization signature
                    let root_bytes = words_to_bytes(&root);
                    assert!(self
                        .auth_pk
                        .unwrap()
                        .verify(root_bytes, &self.auth_sig.unwrap())
                        .is_ok());
                }

                // Do nothing when creating a persistent resource;

                // return empty external_payload and application_payload
                (resource_ciphertext, vec![], vec![])
            };

        let app_data = AppData {
            resource_payload,
            discovery_payload,
            external_payload,
            application_payload,
        };

        LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.is_consumed,
            root,
            app_data,
        }
    }
}

impl SimpleTransferWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        is_consumed: bool,
        resource: Resource,
        existence_path: MerklePath,
        nf_key: Option<NullifierKey>,
        auth_pk: Option<AuthorizationVerifyingKey>,
        auth_sig: Option<AuthorizationSignature>,
        forwarder_sig: Option<Vec<u8>>,
        discovery_pk: AffinePoint,
        encryption_pk: Option<AffinePoint>,
        encryption_sk: Option<SecretKey>,
        encryption_nonce: Option<[u8; 12]>,
        forwarder_addr: Option<Vec<u8>>,
        erc20_addr: Option<Vec<u8>>,
        user_addr: Option<Vec<u8>>,
    ) -> Self {
        Self {
            is_consumed,
            resource,
            existence_path,
            nf_key,
            auth_pk,
            auth_sig,
            forwarder_sig,
            discovery_pk,
            discovery_sk: SecretKey::random(),
            discovery_nonce: rand::random(),
            encryption_pk,
            encryption_sk,
            encryption_nonce,
            forwarder_addr,
            erc20_addr,
            user_addr,
        }
    }
}
