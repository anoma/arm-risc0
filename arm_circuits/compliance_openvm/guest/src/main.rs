use openvm as _;
use openvm_sha2::sha256;

openvm::init!();

mod compliance;

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
