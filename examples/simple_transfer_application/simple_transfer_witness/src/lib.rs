pub use arm::resource_logic::LogicCircuit;
use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{AffinePoint, Ciphertext, SecretKey},
    error::ArmError,
    evm::{
        encode_migrate, encode_permit_witness_transfer_from, encode_transfer, CallType,
        ForwarderCalldata, PermitTransferFrom,
    },
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, hash_bytes},
    Digest,
};
use hex::FromHex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref ROOT_V1: Digest =
        Digest::from_hex("c14edf4cb99988b690d94516864e220d5bf6bde294aad5b6dbf385830f2c3135")
            .unwrap();
    pub static ref FORWARDER_ADDRESS_V1: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
    pub static ref LOGIC_V1: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SimpleTransferWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub action_tree_root: Digest,
    pub nf_key: Option<NullifierKey>,
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
    // The discovery ciphertext for the resource
    pub discovery_cipher: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub call_type: CallType,
    pub forwarder_addr: Vec<u8>,
    pub token_addr: Vec<u8>,
    pub user_addr: Vec<u8>,
    pub permit_info: Option<PermitInfo>,
    pub migrate_info: Option<MigrateInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermitInfo {
    pub permit_nonce: Vec<u8>,
    pub permit_deadline: Vec<u8>,
    pub permit_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrateInfo {
    pub resource: Resource,
    pub nf_key: NullifierKey,
    pub path: MerklePath,
}

impl LogicCircuit for SimpleTransferWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        // Load resources
        let cm = self.resource.commitment();
        let tag = if self.is_consumed {
            let nf_key = self
                .nf_key
                .as_ref()
                .ok_or(ArmError::MissingField("Nullifier key"))?;
            self.resource.nullifier_from_commitment(nf_key, &cm)?
        } else {
            cm
        };

        let root_bytes = self.action_tree_root.as_bytes();

        // Generate resource_payload and external_payload
        let (discovery_payload, resource_payload, external_payload) = if self.resource.is_ephemeral
        {
            let forwarder_info = self
                .forwarder_info
                .as_ref()
                .ok_or(ArmError::MissingField("Forwarder info"))?;
            // Check resource label: label = sha2(forwarder_addr, erc20_addr)
            let forwarder_addr = forwarder_info.forwarder_addr.as_ref();
            let erc20_addr = forwarder_info.token_addr.as_ref();
            let user_addr = forwarder_info.user_addr.as_ref();
            let label_ref = calculate_label_ref(forwarder_addr, erc20_addr);
            assert_eq!(self.resource.label_ref, label_ref);

            // Check resource value_ref: value_ref[0..20] = user_addr
            let value_ref = calculate_value_ref_from_user_addr(user_addr);
            assert_eq!(self.resource.value_ref, value_ref);

            let input = match forwarder_info.call_type {
                CallType::Unwrap => {
                    // Burning
                    assert!(!self.is_consumed);
                    encode_transfer(erc20_addr, user_addr, self.resource.quantity)
                }
                CallType::Wrap => {
                    // Minting
                    assert!(self.is_consumed);
                    let permit_info = forwarder_info
                        .permit_info
                        .as_ref()
                        .ok_or(ArmError::MissingField("Permit info"))?;
                    let permit = PermitTransferFrom::from_bytes(
                        erc20_addr,
                        self.resource.quantity,
                        permit_info.permit_nonce.as_ref(),
                        permit_info.permit_deadline.as_ref(),
                    );
                    encode_permit_witness_transfer_from(
                        user_addr,
                        permit,
                        root_bytes,
                        permit_info.permit_sig.as_ref(),
                    )
                }
                CallType::Migrate => {
                    assert!(self.is_consumed);

                    let migrate_info = forwarder_info
                        .migrate_info
                        .as_ref()
                        .ok_or(ArmError::MissingField("Migrate info"))?;

                    // check existence of migrate_resource
                    let migrate_cm = migrate_info.resource.commitment();
                    let migrate_root = migrate_info.path.root(&migrate_cm);
                    assert_eq!(*ROOT_V1, migrate_root);

                    // check migrate_resource logic_ref
                    assert_eq!(
                        migrate_info.resource.logic_ref.as_words(),
                        LOGIC_V1.as_words()
                    );

                    // check migrate_resource label_ref_v1
                    let migrate_label_ref_v1 =
                        calculate_label_ref(FORWARDER_ADDRESS_V1.as_bytes(), erc20_addr);
                    assert_eq!(migrate_info.resource.label_ref, migrate_label_ref_v1);

                    // check migrate_resource quantity
                    assert_eq!(migrate_info.resource.quantity, self.resource.quantity);

                    // compute migrate resource nullifier
                    let migrate_nf = migrate_info
                        .resource
                        .nullifier_from_commitment(&migrate_info.nf_key, &migrate_cm)?;

                    encode_migrate(erc20_addr, self.resource.quantity, migrate_nf.as_bytes())
                }
                _ => {
                    return Err(ArmError::MissingField(
                        "Invalid call type for ephemeral resource",
                    ));
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

            // Empty discovery_payload and resource_payload
            (vec![], vec![], external_payload)
        } else {
            // Consume a persistent resource
            if self.is_consumed {
                let auth_info = self
                    .auth_info
                    .as_ref()
                    .ok_or(ArmError::MissingField("Auth info"))?;
                let auth_pk = auth_info.auth_pk;
                // check value_ref
                assert_eq!(
                    self.resource.value_ref,
                    calculate_value_ref_from_auth(&auth_pk)
                );
                // Verify the authorization signature
                assert!(auth_pk.verify(root_bytes, &auth_info.auth_sig).is_ok());

                // empty payloads for consumed persistent resource
                (vec![], vec![], vec![])
            } else {
                // Generate resource ciphertext
                let encryption_info = self
                    .encryption_info
                    .as_ref()
                    .ok_or(ArmError::MissingField("Encryption info"))?;
                let cipher = Ciphertext::encrypt(
                    &self.resource.to_bytes()?,
                    &encryption_info.encryption_pk,
                    &encryption_info.sender_sk,
                    encryption_info
                        .encryption_nonce
                        .clone()
                        .try_into()
                        .map_err(|_| ArmError::InvalidEncryptionNonce)?,
                )?;
                let cipher_expirable_blob = ExpirableBlob {
                    blob: cipher.as_words(),
                    deletion_criterion: 1,
                };

                // Generate discovery_payload
                let cipher_discovery_blob = ExpirableBlob {
                    blob: encryption_info.discovery_cipher.clone(),
                    deletion_criterion: 1,
                };

                // return discovery_payload and resource_payload
                (
                    vec![cipher_discovery_blob],
                    vec![cipher_expirable_blob],
                    vec![],
                )
            }
        };

        let app_data = AppData {
            resource_payload,
            discovery_payload,
            external_payload,
            application_payload: vec![], // Empty application payload
        };

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed,
            root: self.action_tree_root,
            app_data,
        })
    }
}

impl SimpleTransferWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<NullifierKey>,
        auth_info: Option<AuthorizationInfo>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
    ) -> Self {
        Self {
            is_consumed,
            resource,
            action_tree_root,
            nf_key,
            auth_info,
            encryption_info,
            forwarder_info,
        }
    }
}

pub fn calculate_value_ref_from_auth(auth_pk: &AuthorizationVerifyingKey) -> Digest {
    hash_bytes(&auth_pk.to_bytes())
}

pub fn calculate_value_ref_from_user_addr(user_addr: &[u8]) -> Digest {
    let mut addr_padded = [0u8; 32];
    addr_padded[0..20].copy_from_slice(user_addr);
    Digest::from_bytes(addr_padded)
}

pub fn get_user_addr(value_ref: &Digest) -> [u8; 20] {
    let bytes = value_ref.as_bytes();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes[0..20]);
    addr
}

pub fn calculate_label_ref(forwarder_add: &[u8], erc20_add: &[u8]) -> Digest {
    hash_bytes(&[forwarder_add, erc20_add].concat())
}

impl EncryptionInfo {
    pub fn new(encryption_pk: AffinePoint, discovery_pk: &AffinePoint) -> Self {
        let discovery_nonce: [u8; 12] = rand::random();
        let discovery_sk = SecretKey::random();
        let discovery_cipher = Ciphertext::encrypt(
            &vec![0u8],
            discovery_pk,
            &discovery_sk,
            discovery_nonce
                .as_slice()
                .try_into()
                .expect("Failed to convert discovery nonce, it cannot fail"),
        )
        .unwrap()
        .as_words();
        let sender_sk = SecretKey::random();
        let encryption_nonce: [u8; 12] = rand::random();
        Self {
            encryption_pk,
            sender_sk,
            encryption_nonce: encryption_nonce.to_vec(),
            discovery_cipher,
        }
    }
}
