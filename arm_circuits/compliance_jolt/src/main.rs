use std::time::Instant;

fn main() {
    println!("Compiling guest...");
    let target_dir = "/tmp/jolt-compliance-inline";
    let mut program = guest::compile_compliance_prove(target_dir);

    println!("Preprocessing...");
    let shared_pp = guest::preprocess_shared_compliance_prove(&mut program).unwrap();
    let prover_pp = guest::preprocess_prover_compliance_prove(shared_pp.clone());
    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp = guest::preprocess_verifier_compliance_prove(shared_pp, verifier_setup, None);

    let prove = guest::build_prover_compliance_prove(program, prover_pp);
    let verify = guest::build_verifier_compliance_prove(verifier_pp);

    println!("Proving compliance circuit (with inlines)...");
    let start = Instant::now();
    let (output, proof, io_device) = prove();
    let prove_duration = start.elapsed();

    let (lo, hi) = output;
    println!("\n=== Proof generated in {:?} ===", prove_duration);
    println!("Instance hash: 0x{:032x}{:032x}", hi, lo);

    println!("\nVerifying...");
    let start = Instant::now();
    let is_valid = verify(output, io_device.panic, proof);
    let verify_duration = start.elapsed();
    println!("Verification: {} ({:?})", is_valid, verify_duration);
}
