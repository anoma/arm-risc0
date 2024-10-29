use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
    Receipt,
    sha::{Impl, Sha256, Digest}
};
use rand::Rng;
use aarm_core::{Compliance, Resource, Nsk};
use methods::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};
use rustler::{NifResult, Error};


#[rustler::nif]
fn prove(
    env_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<Vec<u8>> {
    
    // let compliance: Compliance<32> = Compliance::<32>::default();
    // let compliance_bytes = borsh::to_vec(&compliance).expect("Failed to serialize compliance");

    // let env = ExecutorEnv::builder()
    //     .write(&compliance_bytes)
    //     .expect("Failed to write to ExecutorEnv")
    //     .build()
    //     .expect("Failed to build ExecutorEnv");

    // let prover = default_prover();
    // println!("Proving");
    // // Produce a receipt by proving the specified ELF binary.
    // let receipt = prover
    //     .prove(env, COMPLIANCE_GUEST_ELF)
    //     .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to prove: {:?}", e))))?
    //     // .map_err(|e| format!("Failed to prove: {:?}", e))?
    //     .receipt;
    let env = ExecutorEnv::builder()
        .write(&env_bytes)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    println!("Proving");
    let receipt = prover
        .prove(env, COMPLIANCE_GUEST_ELF)
        .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to prove: {:?}", e))))?
        .receipt;
    println!("Proved");
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    println!("bytes");
    Ok(receipt_bytes)
}

#[rustler::nif]
fn verify(
    receipt_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<bool> {
    let receipt: Receipt = borsh::from_slice(&receipt_bytes).unwrap();
    let elf_digest : Digest = borsh::from_slice(&elf).unwrap();
    receipt
        .verify(elf_digest)
        .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to verify: {:?}", e))))?;
    Ok(true)
}

#[rustler::nif]
fn generate_resource(
    label: Vec<u8>,
    nonce: Vec<u8>,
    quantity: Vec<u8>,
    value: Vec<u8>,
    eph: Vec<u8>,
    nsk: Vec<u8>,
    image_id: Vec<u8>,
    rseed: Vec<u8>
) -> NifResult<Vec<u8>> {
    let nk: Nsk =  borsh::from_slice(&nsk).unwrap();
    let resource = Resource {
        image_id: *Impl::hash_bytes(&image_id),
        label: borsh::from_slice(&label).unwrap(),
        quantity: borsh::from_slice(&quantity).unwrap(),
        value: borsh::from_slice(&value).unwrap(),
        eph: borsh::from_slice(&eph).unwrap(),
        nonce: *Impl::hash_bytes(&nonce),
        npk: nk.public_key(),
        rseed: borsh::from_slice(&rseed).unwrap(),
    };

    let resource_bytes = borsh::to_vec(&resource).unwrap();
    Ok(resource_bytes)
}

#[rustler::nif]
fn generate_compliance_circuit(
    input_resource: Vec<u8>,
    output_resource: Vec<u8>,
    rcv: Vec<u8>,
    merkle_path: Vec<u8>,
    nsk: Vec<u8>,
) -> NifResult<Vec<u8>> {
    let compliance = Compliance {
        input_resource: borsh::from_slice(&input_resource).unwrap(),
        output_resource: borsh::from_slice(&output_resource).unwrap(),
        merkle_path: borsh::from_slice::<[(Digest, bool); 32]>(&merkle_path).unwrap(),
        rcv: borsh::from_slice(&rcv).unwrap(),
        nsk: borsh::from_slice(&nsk).unwrap(),
    };
    Ok(borsh::to_vec(&compliance).unwrap())
}

#[rustler::nif]
fn random_32() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    Ok(random_elem.to_vec())
}

#[rustler::nif]
fn generate_merkle_path_32() -> NifResult<Vec<u8>> {
    let mut merkle_path: [(Digest, bool); 32] =
    [(Digest::new([0; 8]), false); 32];

    for i in 0..32 {
        merkle_path[i] = (Digest::new([i as u32 + 1; 8]), i % 2 != 0);
    }
    Ok(borsh::to_vec(&merkle_path).unwrap())
}

#[rustler::nif]
fn generate_nsk() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    let digest = *Impl::hash_bytes(&random_elem);
    Ok(borsh::to_vec(&digest).unwrap())
}

rustler::init!(
    "Elixir.Risc0.Risc0Prover",
    [
        prove,
        verify,
        generate_merkle_path_32,
        generate_resource,
        // risc0_get_output,
        random_32,
        generate_compliance_circuit,
        generate_nsk
    ]
);
