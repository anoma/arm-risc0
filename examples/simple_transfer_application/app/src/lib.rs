pub mod burn;
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
    AuthorizationInfo, EncryptionInfo, ForwarderInfo, PermitInfo, SimpleTransferWitness,
};

pub const SIMPLE_TRANSFER_ELF: &[u8] = include_bytes!("../elf/simple-transfer-guest.bin");
lazy_static! {
    pub static ref SIMPLE_TRANSFER_ID: Digest =
        Digest::from_hex("fbc64b9acd8503080e4f88cd95845e9ae3236b5db351d245407b19545ecd6010")
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
        existence_path: MerklePath,
        nf_key: Option<NullifierKey>,
        auth_info: Option<AuthorizationInfo>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
    ) -> Self {
        Self {
            witness: SimpleTransferWitness::new(
                resource,
                is_consumed,
                existence_path,
                nf_key,
                auth_info,
                encryption_info,
                forwarder_info,
            ),
        }
    }

    pub fn consume_persistent_resource_logic(
        resource: Resource,
        existence_path: MerklePath,
        nf_key: NullifierKey,
        auth_pk: AuthorizationVerifyingKey,
        auth_sig: AuthorizationSignature,
    ) -> Self {
        let auth_info = AuthorizationInfo { auth_pk, auth_sig };
        Self::new(
            resource,
            true,
            existence_path,
            Some(nf_key),
            Some(auth_info),
            None,
            None,
        )
    }

    pub fn create_persistent_resource_logic(
        resource: Resource,
        existence_path: MerklePath,
        discovery_pk: &AffinePoint,
        encryption_pk: AffinePoint,
    ) -> Self {
        let encryption_info = EncryptionInfo::new(encryption_pk, discovery_pk);
        Self::new(
            resource,
            false,
            existence_path,
            None,
            None,
            Some(encryption_info),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint_resource_logic_with_permit(
        resource: Resource,
        existence_path: MerklePath,
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
        };

        Self::new(
            resource,
            true,
            existence_path,
            Some(nf_key),
            None,
            None,
            Some(forwarder_info),
        )
    }

    pub fn burn_resource_logic(
        resource: Resource,
        existence_path: MerklePath,
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
        };

        Self::new(
            resource,
            false,
            existence_path,
            None,
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
