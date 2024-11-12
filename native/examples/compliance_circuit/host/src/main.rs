use aarm_core::{
    compliance::{ComplianceWitness, ComplianceInstance},
    constants::TREE_DEPTH,
    utils::GenericEnv
};
use methods::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::time::Instant;
use serde_bytes::ByteBuf;
use bincode;
pub fn main() {
    let prove_start_timer = Instant::now();

    let compliance_witness: ComplianceWitness<TREE_DEPTH> = ComplianceWitness::<TREE_DEPTH>::default();
    let generic_env = GenericEnv {
        data: ByteBuf::from(bincode::serialize(&compliance_witness).unwrap())
    };

    let env = ExecutorEnv::builder()
        .write(&generic_env)
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
    let compliance_instance: ComplianceInstance = receipt.journal.decode().unwrap();

    let extract_journal_duration = extract_journal_start_timer.elapsed();
    println!(
        "Extract Journal duration time: {:?}",
        extract_journal_duration
    );

    let verify_start_timer = Instant::now();

    receipt.verify(COMPLIANCE_GUEST_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}
