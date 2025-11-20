pub mod burn;
pub mod migrate;
pub mod mint;
pub mod resource;
pub mod transfer;
pub mod utils;

use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::AffinePoint,
    evm::CallType,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    Digest,
};
use hex::FromHex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use simple_transfer_witness::{
    AuthorizationInfo, EncryptionInfo, ForwarderInfo, MigrateInfo, PermitInfo,
    SimpleTransferWitness,
};

pub const SIMPLE_TRANSFER_ELF: &[u8] = include_bytes!("../elf/simple-transfer-guest.bin");
lazy_static! {
    pub static ref SIMPLE_TRANSFER_ID: Digest =
        Digest::from_hex("c751f1439528fd7cff79027a823a53c409ba86b70e0a789671b984e7032c1956")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogic {
    witness: SimpleTransferWitness,
}

impl TransferLogic {
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
            witness: SimpleTransferWitness::new(
                resource,
                is_consumed,
                action_tree_root,
                nf_key,
                auth_info,
                encryption_info,
                forwarder_info,
            ),
        }
    }

    pub fn consume_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        auth_pk: AuthorizationVerifyingKey,
        auth_sig: AuthorizationSignature,
    ) -> Self {
        let auth_info = AuthorizationInfo { auth_pk, auth_sig };
        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            Some(auth_info),
            None,
            None,
        )
    }

    pub fn create_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        discovery_pk: &AffinePoint,
        encryption_pk: AffinePoint,
    ) -> Self {
        let encryption_info = EncryptionInfo::new(encryption_pk, discovery_pk);
        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            Some(encryption_info),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint_resource_logic_with_permit(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        forwarder_addr: Vec<u8>,
        token_addr: Vec<u8>,
        user_addr: Vec<u8>,
        permit_nonce: Vec<u8>,
        permit_deadline: Vec<u8>,
        permit_sig: Vec<u8>,
    ) -> Self {
        let permit_info = PermitInfo {
            permit_nonce,
            permit_deadline,
            permit_sig,
        };
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Wrap,
            forwarder_addr,
            token_addr,
            user_addr,
            permit_info: Some(permit_info),
            migrate_info: None,
        };

        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            None,
            None,
            Some(forwarder_info),
        )
    }

    pub fn burn_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        forwarder_addr: Vec<u8>,
        token_addr: Vec<u8>,
        user_addr: Vec<u8>,
    ) -> Self {
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Unwrap,
            forwarder_addr,
            token_addr,
            user_addr,
            permit_info: None,
            migrate_info: None,
        };

        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            None,
            Some(forwarder_info),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn migrate_resource_logic(
        self_resource: Resource,
        action_tree_root: Digest,
        self_nf_key: NullifierKey,
        forwarder_addr: Vec<u8>,
        token_addr: Vec<u8>,
        user_addr: Vec<u8>,
        migrated_resource: Resource,
        migrated_nf_key: NullifierKey,
        migrated_resource_path: MerklePath,
    ) -> Self {
        let migrate_info = MigrateInfo {
            resource: migrated_resource,
            nf_key: migrated_nf_key.clone(),
            path: migrated_resource_path,
        };

        let forwarder_info = ForwarderInfo {
            call_type: CallType::Migrate,
            forwarder_addr,
            token_addr,
            user_addr,
            permit_info: None,
            migrate_info: Some(migrate_info),
        };

        Self::new(
            self_resource,
            true,
            action_tree_root,
            Some(self_nf_key),
            None,
            None,
            Some(forwarder_info),
        )
    }
}

impl LogicProver for TransferLogic {
    type Witness = SimpleTransferWitness;
    fn proving_key() -> &'static [u8] {
        SIMPLE_TRANSFER_ELF
    }

    fn verifying_key() -> Digest {
        *SIMPLE_TRANSFER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}
