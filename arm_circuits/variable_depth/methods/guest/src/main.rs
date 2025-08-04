use risc0_zkvm::sha::Digest;
use risc0_zkvm::guest::env;
use arm::merkle_path::Hashable;

fn main() {
    let (path, leaf): (Vec<(Digest, bool)>, Digest) = env::read();

    let root = path.iter()
            .fold(leaf, |root, (p, leaf_is_on_right)| {
                let p_digest: Digest = Digest::from(p.clone());
                match leaf_is_on_right {
                    false => Digest::combine(&root, &p_digest),
                    true => Digest::combine(&p_digest, &root),
                }
            });

    env::commit(&(root, path.clone(), path.len() as u32));
}
