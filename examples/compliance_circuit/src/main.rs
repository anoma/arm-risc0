use arm::{
    compliance::{ComplianceInstance, ComplianceWitness},
    merkle_path::COMMITMENT_TREE_DEPTH,
};
use compliance_methods::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::time::Instant;

pub fn main() {
    let prove_start_timer = Instant::now();

    let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
        ComplianceWitness::<COMMITMENT_TREE_DEPTH>::default();

    let env = ExecutorEnv::builder()
        .write(&compliance_witness)
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
    let _compliance_instance: ComplianceInstance = receipt.journal.decode().unwrap();

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

#[test]
fn print_compliance_elf_id() {
    // Write the elf binary to a file
    std::fs::write("../../arm/elfs/compliance_pk.bin", COMPLIANCE_GUEST_ELF)
        .expect("Failed to write compliance guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "Compliance Guest ELF ID: {:?}",
        Digest::from(COMPLIANCE_GUEST_ID).as_bytes()
    );
}
