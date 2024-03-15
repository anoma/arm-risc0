#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std]  // std support is experimental


use aarm_core::Resource;
use aarm_core::CreationInput;
use aarm_core::CreationOutput;
use risc0_zkvm::{guest::env, serde};

risc0_zkvm::guest::entry!(main);


fn main() {
    // read the input
    let input: CreationInput = env::read();

    // Get the resource commitment
    let commitment = input.resource.commitment();
    // Finally confirm that the resource logic accepts
    env::verify(input.resource.image_id, &serde::to_vec(&true).unwrap()).unwrap();

    // write public output to the journal
    let output = CreationOutput {
        commitment,
    };
    env::commit(&output);
}
