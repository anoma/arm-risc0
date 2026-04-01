#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use openvm as _;
use openvm_sha2::sha256;

openvm::init!();

use openvm_ecc_test_programs::compliance;

openvm::entry!(main);

pub fn main() {
    let witness_bytes: Vec<u8> = openvm::io::read_vec();
    let witness = compliance::ComplianceWitness::from_bytes(&witness_bytes);
    let instance = witness.constrain();
    let instance_bytes = instance.to_bytes();
    let hash = sha256(&instance_bytes);
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash);
    openvm::io::reveal_bytes32(hash_arr);
}
