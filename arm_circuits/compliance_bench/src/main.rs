use anoma_rm_risc0::compliance::ComplianceWitness;
use anoma_rm_risc0::compliance_unit::ComplianceUnit;
use anoma_rm_risc0::proving_system::ProofType;
use std::time::Instant;

fn main() {
    let witness = ComplianceWitness::default();

    println!("Generating risc0 STARK (succinct) compliance proof...");
    let start = Instant::now();
    let unit = ComplianceUnit::create(&witness, ProofType::Succinct)
        .expect("compliance proof failed");
    let prove_duration = start.elapsed();

    println!("\n=== Proof generated in {:?} ===", prove_duration);
    println!("Instance: {} bytes", unit.instance.len());
    println!("Proof present: {}", unit.proof.is_some());

    println!("\nVerifying...");
    let start = Instant::now();
    unit.verify().expect("verification failed");
    let verify_duration = start.elapsed();
    println!("Verification: OK ({:?})", verify_duration);
}
