use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey},
    error::ArmError,
};

pub fn authorize_the_action(
    auth_sk: &AuthorizationSigningKey,
    action_tree: &MerkleTree,
) -> Result<AuthorizationSignature, ArmError> {
    let action_tree_root = action_tree.root()?;
    Ok(auth_sk.sign(action_tree_root.as_bytes()))
}
