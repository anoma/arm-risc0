use crate::TransferLogic;
use arm::{
    authorization::AuthorizationVerifyingKey, logic_proof::LogicProver,
    nullifier_key::NullifierKeyCommitment, resource::Resource, Digest,
};
use simple_transfer_witness::{calculate_label_ref, calculate_value_ref_from_auth};

#[allow(clippy::too_many_arguments)]
pub fn construct_persistent_resource(
    forwarder_addr: &[u8],
    token_addr: &[u8],
    quantity: u128,
    nonce: [u8; 32],
    nk_commitment: NullifierKeyCommitment,
    rand_seed: [u8; 32],
    auth_pk: &AuthorizationVerifyingKey,
) -> Resource {
    let label_ref = calculate_label_ref(forwarder_addr, token_addr);
    let value_ref = calculate_value_ref_from_auth(auth_pk);
    Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref,
        quantity,
        value_ref,
        is_ephemeral: false,
        nonce,
        nk_commitment,
        rand_seed,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn construct_ephemeral_resource(
    forwarder_addr: &[u8],
    token_addr: &[u8],
    quantity: u128,
    nonce: [u8; 32],
    nk_commitment: NullifierKeyCommitment,
    rand_seed: [u8; 32],
) -> Resource {
    let label_ref = calculate_label_ref(forwarder_addr, token_addr);
    Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref,
        quantity,
        value_ref: Digest::from([0u8; 32]),
        is_ephemeral: true,
        nonce,
        nk_commitment,
        rand_seed,
    }
}
