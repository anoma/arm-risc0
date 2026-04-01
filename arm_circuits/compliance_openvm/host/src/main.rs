use openvm_build::GuestOptions;
use openvm_sdk::{Sdk, StdIn};
use std::time::Instant;

fn main() -> eyre::Result<()> {
    let sdk = Sdk::riscv32();
    let guest_path = "../guest";

    println!("Building guest...");
    let elf = sdk.build(GuestOptions::default(), guest_path, &None, None)?;

    // Construct default witness (same as guest's Default impl)
    let witness_bytes = build_default_witness();
    println!("Witness: {} bytes", witness_bytes.len());

    let mut stdin = StdIn::default();
    stdin.write_bytes(&witness_bytes);

    println!("Executing (dry run)...");
    let output = sdk.execute(elf.clone(), stdin.clone())?;
    println!("Execution output: {:?}", &output[..std::cmp::min(32, output.len())]);

    println!("Proving...");
    let start = Instant::now();
    let (proof, app_commit) = sdk.prove(elf, stdin)?;
    let prove_duration = start.elapsed();

    println!("\n=== Proof generated in {:?} ===", prove_duration);

    println!("Verifying...");
    let start = Instant::now();
    let (_agg_pk, agg_vk) = sdk.agg_keygen()?;
    Sdk::verify_proof(&agg_vk, app_commit, &proof)?;
    let verify_duration = start.elapsed();
    println!("Verification: OK ({:?})", verify_duration);

    Ok(())
}

/// Build the default ComplianceWitness bytes (mirrors guest-side Default impl)
fn build_default_witness() -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let hash = |data: &[u8]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    };

    let nf_key = [0u8; 32];
    let nk_commitment = hash(&nf_key);

    // consumed resource
    let mut consumed = Vec::new();
    consumed.extend_from_slice(&[0u8; 32]); // logic_ref
    consumed.extend_from_slice(&[0u8; 32]); // label_ref
    consumed.extend_from_slice(&1u128.to_be_bytes()); // quantity
    consumed.extend_from_slice(&[0u8; 32]); // value_ref
    consumed.push(0); // is_ephemeral = false
    consumed.extend_from_slice(&[0u8; 32]); // nonce
    consumed.extend_from_slice(&nk_commitment); // nk_commitment
    consumed.extend_from_slice(&[0u8; 32]); // rand_seed

    // compute nullifier of consumed resource
    // psi = hash(personalization || PSI_TAG || rand_seed || nonce)
    let mut psi_input = Vec::new();
    psi_input.extend_from_slice(b"RISC0_ExpandSeed");
    psi_input.push(0); // PSI tag
    psi_input.extend_from_slice(&[0u8; 32]); // rand_seed
    psi_input.extend_from_slice(&[0u8; 32]); // nonce
    let psi = hash(&psi_input);

    // rcm = hash(personalization || RCM_TAG || rand_seed || nonce)
    let mut rcm_input = Vec::new();
    rcm_input.extend_from_slice(b"RISC0_ExpandSeed");
    rcm_input.push(1); // RCM tag
    rcm_input.extend_from_slice(&[0u8; 32]);
    rcm_input.extend_from_slice(&[0u8; 32]);
    let rcm = hash(&rcm_input);

    // commitment = hash(logic_ref || label_ref || quantity || value_ref || ephemeral || nonce || nk_cm || rcm)
    let mut cm_input = Vec::new();
    cm_input.extend_from_slice(&[0u8; 32]); // logic_ref
    cm_input.extend_from_slice(&[0u8; 32]); // label_ref
    cm_input.extend_from_slice(&1u128.to_be_bytes());
    cm_input.extend_from_slice(&[0u8; 32]); // value_ref
    cm_input.push(0); // not ephemeral
    cm_input.extend_from_slice(&[0u8; 32]); // nonce
    cm_input.extend_from_slice(&nk_commitment);
    cm_input.extend_from_slice(&rcm);
    let cm = hash(&cm_input);

    // nullifier = hash(nf_key || nonce || psi || cm)
    let mut nf_input = Vec::new();
    nf_input.extend_from_slice(&nf_key);
    nf_input.extend_from_slice(&[0u8; 32]); // nonce
    nf_input.extend_from_slice(&psi);
    nf_input.extend_from_slice(&cm);
    let nf = hash(&nf_input);

    // created resource (nonce = nullifier)
    let mut created = Vec::new();
    created.extend_from_slice(&[0u8; 32]); // logic_ref
    created.extend_from_slice(&[0u8; 32]); // label_ref
    created.extend_from_slice(&1u128.to_be_bytes()); // quantity
    created.extend_from_slice(&[0u8; 32]); // value_ref
    created.push(0); // not ephemeral
    created.extend_from_slice(&nf); // nonce = consumed nullifier
    created.extend_from_slice(&nk_commitment);
    created.extend_from_slice(&[0u8; 32]); // rand_seed

    // assemble witness
    let mut witness = Vec::new();
    witness.extend_from_slice(&consumed);
    witness.extend_from_slice(&created);
    witness.extend_from_slice(&hex::decode("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06").unwrap()); // ephemeral_root
    witness.extend_from_slice(&nf_key);
    witness.push(10); // merkle path length
    for _ in 0..10 {
        witness.extend_from_slice(&[0u8; 32]); // digest
        witness.push(0); // is_right = false
    }
    let mut rcv = [0u8; 32];
    rcv[0] = 1; // LE 1
    witness.extend_from_slice(&rcv);
    witness
}
