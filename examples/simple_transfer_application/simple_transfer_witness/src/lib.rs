pub use arm::resource_logic::LogicCircuit;
use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{AffinePoint, Ciphertext, SecretKey},
    evm::{
        encode_permit_witness_transfer_from, encode_transfer, encode_transfer_from, CallType,
        ForwarderCalldata, PermitTransferFrom, Resource as EvmResource,
    },
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
    // user(from or to) address in externalPayload used for erc20 call
    pub user_addr: Option<Vec<u8>>,
    // call type in externalPayload used for erc20 call
    pub call_type: Option<CallType>,
    pub permit_nonce: Option<Vec<u8>>,
    pub permit_deadline: Option<Vec<u8>>,
}

impl LogicCircuit for SimpleTransferWitness {
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
        let root_bytes = words_to_bytes(&root);

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
                let label_ref = calculate_label_ref(forwarder_addr, erc20_addr, user_addr);
                assert_eq!(self.resource.label_ref, label_ref);

                // Check resource value_ref: value_ref = sha2(call_type, user_addr)
                let call_type = self.call_type.as_ref().unwrap();
                let value_ref = calculate_value_ref_calltype_user(*call_type, user_addr);
                assert_eq!(self.resource.value_ref, value_ref);

                if self.is_consumed {
                    // Minting
                    assert!(
                        *call_type == CallType::TransferFrom
                            || *call_type == CallType::PermitWitnessTransferFrom
                    );
                } else {
                    // Burning
                    assert_eq!(*call_type, CallType::Transfer);
                };

                let input = match call_type {
                    CallType::Transfer => {
                        encode_transfer(erc20_addr, user_addr, self.resource.quantity)
                    }
                    CallType::TransferFrom => {
                        encode_transfer_from(erc20_addr, user_addr, self.resource.quantity)
                    }
                    CallType::PermitWitnessTransferFrom => {
                        let permit = PermitTransferFrom::from_bytes(
                            erc20_addr,
                            self.resource.quantity,
                            self.permit_nonce.as_ref().unwrap(),
                            self.permit_deadline.as_ref().unwrap(),
                        );
                        encode_permit_witness_transfer_from(
                            user_addr,
                            permit,
                            root_bytes,
                            self.forwarder_sig.as_ref().unwrap().to_vec(),
                        )
                    }
                    _ => {
                        panic!("Unsupported call type");
                    }
                };

                let forwarder_call_data =
                    ForwarderCalldata::from_bytes(forwarder_addr, input, vec![]);
                let external_payload = {
                    let call_data_expirable_blob = ExpirableBlob {
                        blob: bytes_to_words(&forwarder_call_data.encode()),
                        deletion_criterion: 1,
                    };
                    vec![call_data_expirable_blob]
                };

                (resource_payload, external_payload, vec![])
            } else {
                // Generate resource ciphertext
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
                    let auth_pk = self.auth_pk.as_ref().unwrap();
                    // check value_ref
                    assert_eq!(
                        self.resource.value_ref,
                        calculate_value_ref_from_auth(auth_pk)
                    );
                    // Verify the authorization signature
                    assert!(auth_pk.verify(root_bytes, &self.auth_sig.unwrap()).is_ok());
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
        call_type: Option<CallType>,
        permit_nonce: Option<Vec<u8>>,
        permit_deadline: Option<Vec<u8>>,
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
            call_type,
            permit_nonce,
            permit_deadline,
        }
    }
}

pub fn calculate_value_ref_from_auth(auth_pk: &AuthorizationVerifyingKey) -> Vec<u8> {
    hash_bytes(&auth_pk.to_bytes())
}

pub fn calculate_value_ref_calltype_user(call_type: CallType, user_addr: &[u8]) -> Vec<u8> {
    let mut data = vec![call_type as u8];
    data.extend_from_slice(user_addr);
    hash_bytes(&data)
}

pub fn calculate_label_ref(forwarder_add: &[u8], erc20_add: &[u8], user_add: &[u8]) -> Vec<u8> {
    hash_bytes(&[forwarder_add, erc20_add, user_add].concat())
}
