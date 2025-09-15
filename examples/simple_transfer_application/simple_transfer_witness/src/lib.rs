pub use arm::resource_logic::LogicCircuit;
use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{AffinePoint, Ciphertext, SecretKey},
    evm::{
        encode_permit_witness_transfer_from, encode_transfer, CallType, ForwarderCalldata,
        PermitTransferFrom, Resource as EvmResource,
    },
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, hash_bytes, words_to_bytes},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SimpleTransferWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub existence_path: MerklePath,
    pub nf_key: Option<NullifierKey>,
    pub discovery_cipher: Vec<u32>,
    pub auth_info: Option<AuthorizationInfo>,
    pub encryption_info: Option<EncryptionInfo>,
    pub forwarder_info: Option<ForwarderInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationInfo {
    // The authorization verifying key corresponds to the resource.value.owner
    pub auth_pk: AuthorizationVerifyingKey,
    // A consumed persistent resource requires an authorization signature
    pub auth_sig: AuthorizationSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionInfo {
    // Obtain from the receiver for persistent resource_ciphertext
    pub encryption_pk: AffinePoint,
    // randomly generated for persistent resource_ciphertext
    pub sender_sk: SecretKey,
    // randomly generated for persistent resource_ciphertext(12 bytes)
    pub encryption_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub call_type: CallType,
    pub forwarder_addr: Vec<u8>,
    pub token_addr: Vec<u8>,
    pub user_addr: Vec<u8>,
    pub permit_info: Option<PermitInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermitInfo {
    pub permit_nonce: Vec<u8>,
    pub permit_deadline: Vec<u8>,
    pub permit_sig: Vec<u8>,
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
            let cipher_expirable_blob = ExpirableBlob {
                blob: self.discovery_cipher.clone(),
                deletion_criterion: 1,
            };
            vec![cipher_expirable_blob]
        };

        // Generate external_payload and application_payload
        let (resource_payload, external_payload, application_payload) = if self
            .resource
            .is_ephemeral
        {
            // Generate resource_payload
            let resource_payload = {
                let encoded_resource = if self.is_consumed {
                    // Consuming an ephemeral resource, include the nullifier key
                    let nk = self.nf_key.as_ref().unwrap().inner();
                    EvmResource::from(self.resource.clone()).encode_with_nk(nk)
                } else {
                    // Creating an ephemeral resource, do not include the nullifier key
                    EvmResource::from(self.resource.clone()).encode()
                };
                let encoded_resource_expirable_blob = ExpirableBlob {
                    blob: bytes_to_words(&encoded_resource),
                    deletion_criterion: 0,
                };

                vec![encoded_resource_expirable_blob]
            };

            // Check resource label: label = sha2(forwarder_addr, erc20_addr)
            let forwarder_addr = self
                .forwarder_info
                .as_ref()
                .unwrap()
                .forwarder_addr
                .as_ref();
            let erc20_addr = self.forwarder_info.as_ref().unwrap().token_addr.as_ref();
            let user_addr = self.forwarder_info.as_ref().unwrap().user_addr.as_ref();
            let label_ref = calculate_label_ref(forwarder_addr, erc20_addr);
            assert_eq!(self.resource.label_ref, label_ref);

            // Check resource value_ref: value_ref = sha2(call_type, user_addr)
            let call_type = self.forwarder_info.as_ref().unwrap().call_type;
            let value_ref = calculate_value_ref_calltype_user(call_type, user_addr);
            assert_eq!(self.resource.value_ref, value_ref);

            if self.is_consumed {
                // Minting
                assert_eq!(call_type, CallType::Wrap);
            } else {
                // Burning
                assert_eq!(call_type, CallType::Unwrap);
            };

            let input = match call_type {
                CallType::Unwrap => encode_transfer(erc20_addr, user_addr, self.resource.quantity),
                // CallType::TransferFrom => {
                //     encode_transfer_from(erc20_addr, user_addr, self.resource.quantity)
                // }
                CallType::Wrap => {
                    let permit = PermitTransferFrom::from_bytes(
                        erc20_addr,
                        self.resource.quantity,
                        self.forwarder_info
                            .as_ref()
                            .unwrap()
                            .permit_info
                            .as_ref()
                            .unwrap()
                            .permit_nonce
                            .as_ref(),
                        self.forwarder_info
                            .as_ref()
                            .unwrap()
                            .permit_info
                            .as_ref()
                            .unwrap()
                            .permit_deadline
                            .as_ref(),
                    );
                    encode_permit_witness_transfer_from(
                        user_addr,
                        permit,
                        root_bytes,
                        self.forwarder_info
                            .as_ref()
                            .unwrap()
                            .permit_info
                            .as_ref()
                            .unwrap()
                            .permit_sig
                            .as_ref(),
                    )
                }
                _ => {
                    panic!("Unsupported call type");
                }
            };

            let forwarder_call_data = ForwarderCalldata::from_bytes(forwarder_addr, input, vec![]);
            let external_payload = {
                let call_data_expirable_blob = ExpirableBlob {
                    blob: bytes_to_words(&forwarder_call_data.encode()),
                    deletion_criterion: 0,
                };
                vec![call_data_expirable_blob]
            };

            (resource_payload, external_payload, vec![])
        } else {
            // Consume a persistent resource
            let resource_ciphertext = if self.is_consumed {
                let auth_pk = self.auth_info.as_ref().unwrap().auth_pk;
                // check value_ref
                assert_eq!(
                    self.resource.value_ref,
                    calculate_value_ref_from_auth(&auth_pk)
                );
                // Verify the authorization signature
                assert!(auth_pk
                    .verify(root_bytes, &self.auth_info.as_ref().unwrap().auth_sig)
                    .is_ok());

                // resource_ciphertext is empty
                vec![]
            } else {
                // Generate resource ciphertext
                let cipher = Ciphertext::encrypt(
                    &self.resource.to_bytes(),
                    &self.encryption_info.as_ref().unwrap().encryption_pk,
                    &self.encryption_info.as_ref().unwrap().sender_sk,
                    self.encryption_info
                        .as_ref()
                        .unwrap()
                        .encryption_nonce
                        .clone()
                        .try_into()
                        .expect("Failed to convert encryption_nonce"),
                );
                let cipher_expirable_blob = ExpirableBlob {
                    blob: cipher.as_words(),
                    deletion_criterion: 1,
                };
                vec![cipher_expirable_blob]
            };

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
        resource: Resource,
        is_consumed: bool,
        existence_path: MerklePath,
        nf_key: Option<NullifierKey>,
        discovery_cipher: Vec<u32>,
        auth_info: Option<AuthorizationInfo>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
    ) -> Self {
        Self {
            is_consumed,
            resource,
            existence_path,
            nf_key,
            discovery_cipher,
            auth_info,
            encryption_info,
            forwarder_info,
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

pub fn calculate_label_ref(forwarder_add: &[u8], erc20_add: &[u8]) -> Vec<u8> {
    hash_bytes(&[forwarder_add, erc20_add].concat())
}
