use std::time::Instant;

use openvm_build::GuestOptions;
use openvm_sdk::{
    config::{default_app_params, AggregationSystemParams, DEFAULT_APP_LOG_BLOWUP, DEFAULT_APP_L_SKIP},
    Sdk, StdIn,
};

fn main() -> eyre::Result<()> {
    let n_stack = 22;
    let app_params = default_app_params(DEFAULT_APP_LOG_BLOWUP, DEFAULT_APP_L_SKIP, n_stack);
    let agg_params = AggregationSystemParams::default();
    let sdk = Sdk::standard(app_params, agg_params);

    println!("Building guest...");
    let elf = sdk.build(GuestOptions::default(), "../guest", &None, None)?;

    let witness_bytes = build_default_witness();
    println!("Witness: {} bytes", witness_bytes.len());

    let mut stdin = StdIn::default();
    stdin.write_bytes(&witness_bytes);

    println!("Executing...");
    let exe = sdk.convert_to_exe(elf.clone())?;
    let output = sdk.execute(exe.clone(), stdin.clone())?;
    println!("Execution output: {} bytes", output.len());

    println!("Proving...");
    let start = Instant::now();
    let (proof, baseline) = sdk.prove(exe, stdin)?;
    let prove_time = start.elapsed();
    println!("\n=== Proof generated in {:?} ===", prove_time);

    println!("Verifying...");
    let start = Instant::now();
    Sdk::verify_proof(&baseline, &proof)?;
    println!("Verification: OK ({:?})", start.elapsed());

    Ok(())
}

fn build_default_witness() -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let hash = |data: &[u8]| -> [u8; 32] { Sha256::digest(data).into() };
    let nf_key = [0u8; 32];
    let nk_cm = hash(&nf_key);
    let mut consumed = Vec::new();
    consumed.extend_from_slice(&[0u8; 32]); consumed.extend_from_slice(&[0u8; 32]);
    consumed.extend_from_slice(&1u128.to_be_bytes()); consumed.extend_from_slice(&[0u8; 32]);
    consumed.push(0); consumed.extend_from_slice(&[0u8; 32]);
    consumed.extend_from_slice(&nk_cm); consumed.extend_from_slice(&[0u8; 32]);
    let mut psi_in = b"RISC0_ExpandSeed".to_vec(); psi_in.push(0); psi_in.extend_from_slice(&[0u8;64]);
    let psi = hash(&psi_in);
    let mut rcm_in = b"RISC0_ExpandSeed".to_vec(); rcm_in.push(1); rcm_in.extend_from_slice(&[0u8;64]);
    let rcm = hash(&rcm_in);
    let mut cm_in = Vec::new();
    cm_in.extend_from_slice(&[0u8;32]); cm_in.extend_from_slice(&[0u8;32]);
    cm_in.extend_from_slice(&1u128.to_be_bytes()); cm_in.extend_from_slice(&[0u8;32]);
    cm_in.push(0); cm_in.extend_from_slice(&[0u8;32]);
    cm_in.extend_from_slice(&nk_cm); cm_in.extend_from_slice(&rcm);
    let cm = hash(&cm_in);
    let mut nf_in = Vec::new();
    nf_in.extend_from_slice(&nf_key); nf_in.extend_from_slice(&[0u8;32]);
    nf_in.extend_from_slice(&psi); nf_in.extend_from_slice(&cm);
    let nf = hash(&nf_in);
    let mut created = Vec::new();
    created.extend_from_slice(&[0u8;32]); created.extend_from_slice(&[0u8;32]);
    created.extend_from_slice(&1u128.to_be_bytes()); created.extend_from_slice(&[0u8;32]);
    created.push(0); created.extend_from_slice(&nf);
    created.extend_from_slice(&nk_cm); created.extend_from_slice(&[0u8;32]);
    let mut w = Vec::new();
    w.extend_from_slice(&consumed); w.extend_from_slice(&created);
    w.extend_from_slice(&hex::decode("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06").unwrap());
    w.extend_from_slice(&nf_key);
    w.push(10);
    for _ in 0..10 { w.extend_from_slice(&[0u8;32]); w.push(0); }
    let mut rcv = [0u8; 32]; rcv[0] = 1; w.extend_from_slice(&rcv);
    w
}
