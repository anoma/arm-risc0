use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey},
    error::ArmError,
};
use simple_transfer_witness::AUTH_SIGNATURE_DOMAIN;

pub fn authorize_the_action(
    auth_sk: &AuthorizationSigningKey,
    action_tree: &MerkleTree,
) -> Result<AuthorizationSignature, ArmError> {
    let action_tree_root = action_tree.root()?;
    Ok(auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes()))
}
