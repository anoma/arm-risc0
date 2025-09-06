use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey},
    utils::words_to_bytes,
};

pub fn authorize_the_action(
    auth_sk: &AuthorizationSigningKey,
    action_tree: &MerkleTree,
) -> AuthorizationSignature {
    let action_tree_root = action_tree.root();
    auth_sk.sign(words_to_bytes(&action_tree_root))
}
