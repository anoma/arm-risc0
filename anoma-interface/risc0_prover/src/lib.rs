use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
    Receipt,
    sha::Digest
};
use rustler::NifResult;

#[rustler::nif]
fn risc0_prove(
    env_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<Vec<u8>> {
    
    let env = ExecutorEnv::builder()
        .write(&env_bytes)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove(env, &elf).unwrap().receipt;
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    Ok(receipt_bytes)
}

#[rustler::nif]
fn risc0_verify(
    receipt_bytes: Vec<u8>,
    elf: Vec<u8>
) -> NifResult<bool> {
    let receipt: Receipt = borsh::from_slice(&receipt_bytes).unwrap();
    let elf_digest : Digest = borsh::from_slice(&elf).unwrap();
    receipt.verify(elf_digest).unwrap();
    Ok(true)
}

