// #![no_std]
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use methods::{
    COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID
};
use aarm_core::{Compliance, TREE_DEPTH};
use std::time::Instant;

const DATA_BYTES: usize = 32;

pub fn main() {
    let prove_start_timer = Instant::now();

    let compliance = Compliance::<TREE_DEPTH>::default();
    
    let env = ExecutorEnv::builder()
        .write(&compliance)
        .unwrap()
        .build()
        .unwrap();
    
    
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, COMPLIANCE_GUEST_ELF).unwrap().receipt;

    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);


    let extract_journal_start_timer = Instant::now();
    // Extract journal of receipt
    let (_nf, _cm, _merkle_root, _delta): (Digest, Digest, Digest, [u8; DATA_BYTES]) = receipt.journal.decode().unwrap();

    let extract_journal_duration = extract_journal_start_timer.elapsed();
    println!("Extract Journal duration time: {:?}", extract_journal_duration);

    let verify_start_timer = Instant::now();

    receipt.verify(COMPLIANCE_GUEST_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}
