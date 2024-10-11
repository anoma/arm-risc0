use risc0_zkvm::{
    default_prover,
    ExecutorEnv,
    ProverOpts,
    VerifierContext,
};
// use risc0_zkvm_methods::FIB_ELF;

fn risc0_prove(
    trace: Vec<u8>,
    memory: Vec<u8>,
    public_input: Vec<u8>,
) -> NifResult<(Vec<u8>, Vec<u8>)> {
    

    Ok((proof_bytes, pub_input_bytes))
}