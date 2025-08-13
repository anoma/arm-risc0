// use risc0_zkvm::sha::{Impl, Sha256};
use risc0_zkvm::guest::env;
use k256::{
    // elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    ProjectivePoint, Scalar, Secp256k1,
};

// fn main() {
//     let input = Vec::new();
//     for _ in 0..1000 {
//         let _ = *Impl::hash_bytes(input.as_ref());
//     }

//     env::commit(&input);
// }

fn main() {
    let mut pre = ProjectivePoint::GENERATOR;

    let mut cur = ProjectivePoint::GENERATOR + pre;

    let iter = 100;

    for _ in 0..iter {
        let next = pre + cur;
        pre = cur;
        cur = next;
    }
    env::commit(&iter);
}
