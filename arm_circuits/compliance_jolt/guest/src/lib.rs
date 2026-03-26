#![cfg_attr(feature = "guest", no_std)]
extern crate alloc;

pub mod compliance;
pub mod digest;
pub mod error;
pub mod merkle_path;
pub mod nullifier_key;
pub mod resource;
pub mod utils;

/// Takes a serialized ComplianceWitness, runs constraints,
/// returns SHA-256(ComplianceInstance) as (lo_128, hi_128).
#[jolt::provable(heap_size = 67108864, max_trace_length = 67108864)]
fn compliance_prove(witness_bytes: &[u8]) -> (u128, u128) {
    let witness = compliance::ComplianceWitness::from_bytes(witness_bytes);
    let instance = witness.constrain().expect("constrain failed");
    let h = digest::hash_bytes(&instance.to_bytes());
    let b = h.as_bytes();
    let lo = u128::from_le_bytes(b[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(b[16..32].try_into().unwrap());
    (lo, hi)
}
