#![cfg_attr(feature = "guest", no_std)]
extern crate alloc;

pub mod compliance;
pub mod digest;
pub mod error;
pub mod merkle_path;
pub mod nullifier_key;
pub mod resource;
pub mod utils;

/// Returns SHA-256(instance) as (lo_128, hi_128).
/// The instance contains: nullifier, consumed_logic_ref, cm_tree_root,
/// created_commitment, created_logic_ref, delta_x, delta_y.
#[jolt::provable(heap_size = 67108864, max_trace_length = 67108864)]
fn compliance_prove() -> (u128, u128) {
    let witness = compliance::ComplianceWitness::default();
    let instance = witness.constrain().expect("constrain failed");
    let instance_hash = digest::hash_bytes(&instance.to_bytes());
    let b = instance_hash.as_bytes();
    let lo = u128::from_le_bytes(b[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(b[16..32].try_into().unwrap());
    (lo, hi)
}
