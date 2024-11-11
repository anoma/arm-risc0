mod utils;

use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
    Receipt,
    sha::{Impl, Sha256, Digest}
};
use k256::Scalar;
use rand::Rng;
use aarm_core::{
    compliance::Compliance, 
    resource::Resource, 
    nullifier::{Nsk, Npk}, 
    utils::GenericEnv, 
    encryption::{Ciphertext, projective_point_to_bytes, bytes_to_projective_point}};
use rustler::{NifResult, Error};
use utils::{vec_to_array};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::generic_array::GenericArray;
use std::time::Instant;
use serde_bytes::ByteBuf;

#[rustler::nif]
fn prove(
    env_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<Vec<u8>> {
    let generic_env = GenericEnv {
        data: ByteBuf::from(env_bytes),
    };
    let env = ExecutorEnv::builder()
        .write(&generic_env)
        .unwrap()
        .build()
        .unwrap();
    let prover = default_prover();
    println!("Proving...");
    let prove_start_timer = Instant::now();
    let receipt = prover
        .prove(env, &elf)
        .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to prove: {:?}", e))))?
        .receipt;
    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);
    let receipt_bytes = bincode::serialize(&receipt).unwrap();
    Ok(receipt_bytes)
}


#[rustler::nif]
fn verify(
    receipt_bytes: Vec<u8>,
    guest_id_vec: Vec<u32>
) -> NifResult<bool> {
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).unwrap();
    let guest_id: [u32; 8] = match guest_id_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(Error::RaiseTerm(Box::new("compliance_guest_id must have exactly 8 u32 values"))),
    };
    println!("Verifying...");
    let verify_start_timer = Instant::now();
    receipt
    .verify(guest_id)
    .map_err(|e| Error::RaiseTerm(Box::new(format!("Failed to verify: {:?}", e))))?;
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration); 
    Ok(true)
}

#[rustler::nif]
fn generate_resource(
    label: Vec<u8>,
    nonce: Vec<u8>,
    quantity: Vec<u8>,
    data: Vec<u8>,
    eph: bool,
    npk: Vec<u8>,
    logic: Vec<u8>,
    rseed: Vec<u8>
) -> NifResult<Vec<u8>> {
    let resource = Resource {
        logic: *Impl::hash_bytes(&logic),
        label: bincode::deserialize(&label).map_err(|e| Error::RaiseTerm(Box::new(format!("Label deserialization error: {:?}", e)))).unwrap(),
        quantity: bincode::deserialize(&quantity).map_err(|e| Error::RaiseTerm(Box::new(format!("Quantity deserialization error: {:?}", e)))).unwrap(),
        data: bincode::deserialize(&data).map_err(|e| Error::RaiseTerm(Box::new(format!("Data deserialization error: {:?}", e)))).unwrap(),
        eph, 
        nonce: *Impl::hash_bytes(&nonce),
        npk: bincode::deserialize(&npk).map_err(|e| Error::RaiseTerm(Box::new(format!("NPK deserialization error: {:?}", e)))).unwrap(),
        rseed: bincode::deserialize(&rseed).map_err(|e| Error::RaiseTerm(Box::new(format!("Rseed deserialization error: {:?}", e)))).unwrap(),
    };

    let resource_bytes = bincode::serialize(&resource).map_err(|e| Error::RaiseTerm(Box::new(format!("Serialization error: {:?}", e))))?;
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
        input_resource: bincode::deserialize(&input_resource).map_err(|e| Error::RaiseTerm(Box::new(format!("Input resource deserialization error: {:?}", e)))).unwrap(),
        output_resource: bincode::deserialize(&output_resource).map_err(|e| Error::RaiseTerm(Box::new(format!("Output resource deserialization error: {:?}", e)))).unwrap(),
        merkle_path: bincode::deserialize::<[(Digest, bool); 32]>(&merkle_path).map_err(|e| Error::RaiseTerm(Box::new(format!("Merkle path deserialization error: {:?}", e)))).unwrap(),
        rcv: bincode::deserialize(&rcv).map_err(|e| Error::RaiseTerm(Box::new(format!("RCV deserialization error: {:?}", e)))).unwrap(),
        nsk: bincode::deserialize(&nsk).map_err(|e| Error::RaiseTerm(Box::new(format!("NSK deserialization error: {:?}", e)))).unwrap(),
    };

    let compliance_bytes = bincode::serialize(&compliance).map_err(|e| Error::RaiseTerm(Box::new(format!("Serialization error: {:?}", e))))?;
    Ok(compliance_bytes)
}

#[rustler::nif]
fn sha256_single(x: Vec<u8>) -> NifResult<Vec<u8>> {
    let result = Impl::hash_bytes(&x);
    Ok(result.as_bytes().to_vec())
}

#[rustler::nif]
fn sha256_double(x: Vec<u8>, y: Vec<u8>) -> NifResult<Vec<u8>> {
    let mut combined = x;
    combined.extend_from_slice(&y);
    let result = Impl::hash_bytes(&combined);
    Ok(result.as_bytes().to_vec())
}

#[rustler::nif]
fn sha256_many(inputs: Vec<Vec<u8>>) -> NifResult<Vec<u8>> {
    let combined: Vec<u8> = inputs.into_iter().flatten().collect();
    let result = Impl::hash_bytes(&combined);
    Ok(result.as_bytes().to_vec())
}


#[rustler::nif]
fn random_32() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    Ok(random_elem.to_vec())
}

#[rustler::nif]
fn random_merkle_path_32() -> NifResult<Vec<u8>> {
    let mut merkle_path: [(Digest, bool); 32] =
    [(Digest::new([0; 8]), false); 32];

    for i in 0..32 {
        merkle_path[i] = (Digest::new([i as u32 + 1; 8]), i % 2 != 0);
    }
    Ok(bincode::serialize(&merkle_path).unwrap())
}

#[rustler::nif]
fn random_nsk() -> NifResult<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let random_elem: [u8; 32] = rng.gen();
    let digest = *Impl::hash_bytes(&random_elem);
    Ok(bincode::serialize(&digest).unwrap())
}

#[rustler::nif]
fn generate_npk(nsk: Vec<u8>) -> NifResult<Vec<u8>> {
    let nsk: Nsk = bincode::deserialize(&nsk).unwrap();
    let npk: Npk = nsk.public_key();
    Ok(bincode::serialize(&npk).unwrap())
}

#[rustler::nif] 
fn random_keypair() -> NifResult<(Vec<u8>, Vec<u8>)> {
    let (sk, pk) = aarm_core::encryption::random_keypair();
    let pk_bytes = projective_point_to_bytes(&pk);
    Ok((bincode::serialize(&sk).unwrap(), pk_bytes))
}

#[rustler::nif]
fn encrypt(
    message: Vec<u8>,
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
    nonce_bytes: Vec<u8>,
) -> NifResult<Vec<u8>> {
    // Decode pk
    let pk = bytes_to_projective_point(&pk_bytes).unwrap();


    // Decode sk
    let repr = *GenericArray::from_slice(&sk_bytes);
    let sk = Scalar::from_repr(repr).unwrap();

    // Decode nonce
    let nonce = vec_to_array(nonce_bytes).unwrap();

    // Encrypt
    let cipher = Ciphertext::encrypt(&message, &pk, &sk, &nonce);

    Ok(cipher.inner())
}

#[rustler::nif]
fn decrypt(
    cipher: Vec<u8>,
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
    nonce_bytes: Vec<u8>) -> NifResult<Vec<u8>> {
    // Decode pk
    let pk = bytes_to_projective_point(&pk_bytes).unwrap();

    // Decode sk
    let repr = *GenericArray::from_slice(&sk_bytes);
    let sk = Scalar::from_repr(repr).unwrap();

    // Decode nonce
    let nonce = vec_to_array(nonce_bytes).unwrap();
    // Encrypt
    let plaintext = Ciphertext::from(cipher).decrypt(&sk, &pk, &nonce).unwrap();

    Ok(plaintext)
}

rustler::init!(
    "Elixir.Risc0.AarmRustler",
    [
        prove,
        verify,
        random_merkle_path_32,
        generate_resource,
        random_32,
        generate_compliance_circuit,
        random_nsk,
        generate_npk,
        encrypt,
        decrypt,
        random_keypair,
        sha256_single,
        sha256_double,
        sha256_many
    ]
);
