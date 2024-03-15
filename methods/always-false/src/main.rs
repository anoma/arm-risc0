#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std]  // std support is experimental

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);


fn main() {
    // read the input
    let input: () = env::read();

    // do something with the input
    // writing to the journal makes it public
    env::commit(&false);
}
