pub mod transfer;

use arm::{
    authorization::{AuthorizationSignature, AuthorizationVerifyingKey},
    encryption::{AffinePoint, SecretKey},
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
use simple_transfer_witness::SimpleTransferWitness;

pub const SIMPLE_TRANSFER_ELF: &[u8] = include_bytes!("../elf/simple-transfer-guest.bin");
lazy_static! {
    pub static ref SIMPLE_TRANSFER_ID: Digest =
        Digest::from_hex("1349ffc67e29f760efaa0a4e43e76fecc4cc6d54c5f3d346966e4d6de209e6f4")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogic {
    witness: SimpleTransferWitness,
}

impl TransferLogic {
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
            witness: SimpleTransferWitness::new(
                is_consumed,
                resource,
                existence_path,
                nf_key,
                auth_pk,
                auth_sig,
                forwarder_sig,
                discovery_pk,
                encryption_pk,
                encryption_sk,
                encryption_nonce,
                forwarder_addr,
                erc20_addr,
                user_addr,
                call_type,
                permit_nonce,
                permit_deadline,
            ),
        }
    }

    pub fn consume_persistent_resource_logic(
        resource: Resource,
        existence_path: MerklePath,
        nf_key: NullifierKey,
        auth_pk: AuthorizationVerifyingKey,
        auth_sig: AuthorizationSignature,
        discovery_pk: AffinePoint,
        encryption_pk: AffinePoint,
    ) -> Self {
        Self::new(
            true,
            resource,
            existence_path,
            Some(nf_key),
            Some(auth_pk),
            Some(auth_sig),
            None,
            discovery_pk,
            Some(encryption_pk),
            Some(SecretKey::random()),
            Some(rand::random()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    pub fn create_persistent_resource_logic(
        resource: Resource,
        existence_path: MerklePath,
        discovery_pk: AffinePoint,
        encryption_pk: AffinePoint,
    ) -> Self {
        Self::new(
            false,
            resource,
            existence_path,
            None,
            None,
            None,
            None,
            discovery_pk,
            Some(encryption_pk),
            Some(SecretKey::random()),
            Some(rand::random()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    // #[allow(clippy::too_many_arguments)]
    // pub fn mint_resource_logic(
    //     resource: Resource,
    //     existence_path: MerklePath,
    //     nf_key: NullifierKey,
    //     forwarder_sig: Vec<u8>,
    //     discovery_pk: AffinePoint,
    //     forwarder_addr: Vec<u8>,
    //     erc20_addr: Vec<u8>,
    //     user_addr: Vec<u8>,
    // ) -> Self {
    //     Self::new(
    //         true,
    //         resource,
    //         existence_path,
    //         Some(nf_key),
    //         None,
    //         None,
    //         Some(forwarder_sig),
    //         discovery_pk,
    //         None,
    //         None,
    //         None,
    //         Some(forwarder_addr),
    //         Some(erc20_addr),
    //         Some(user_addr),
    //     )
    // }

    // pub fn burn_resource_logic(
    //     resource: Resource,
    //     existence_path: MerklePath,
    //     nf_key: NullifierKey,
    //     discovery_pk: AffinePoint,
    //     forwarder_addr: Vec<u8>,
    //     erc20_addr: Vec<u8>,
    //     user_addr: Vec<u8>,
    // ) -> Self {
    //     Self::new(
    //         false,
    //         resource,
    //         existence_path,
    //         Some(nf_key),
    //         None,
    //         None,
    //         None,
    //         discovery_pk,
    //         None,
    //         None,
    //         None,
    //         Some(forwarder_addr),
    //         Some(erc20_addr),
    //         Some(user_addr),
    //     )
    // }
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
