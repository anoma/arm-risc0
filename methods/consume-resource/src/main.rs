#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std]  // std support is experimental


use aarm_core::Resource;
use aarm_core::ConsumptionInput;
use aarm_core::ConsumptionOutput;
use risc0_zkvm::{guest::env, serde};

risc0_zkvm::guest::entry!(main);


fn main() {
    // read the input
    let input: ConsumptionInput = env::read();

    // Get the resource commitment
    let commitment = input.resource.commitment();
    // Get the root of the Merkle tree
    let root = input.path.root(commitment);
    // Compute the nullifier of the reesource
    let nullifier = input.resource.nullifier(input.nsk).unwrap();
    // Finally confirm that the resource logic accepts
    env::verify(input.resource.image_id, &serde::to_vec(&true).unwrap()).unwrap();

    // write public output to the journal
    let output = ConsumptionOutput {
        root,
        nullifier,
    };
    env::commit(&output);
}
