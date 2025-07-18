use risc0_zkvm::guest::env;
use risc0_zkvm::serde;
use risc0_zkvm::Digest;

///  A sequential aggregation does the following:
///  - verify the step output for the step program,
///  - if not the base case, verify the input aggregation,
///  - hash the step output and step program with the input running hash.
fn main() {
    // Read the (purported) aggregation program ID
    // and input hashes.
    let ag_program_key: Digest = env::read();
    let (h_in, d_in): (Digest, Digest) = env::read();

    // Read the step program ID and (serialized) step output.
    let (step_program, step_output): (Digest, Vec<u32>) = env::read();

    // Verify the step proof.
    env::verify(step_program, &step_output).unwrap();

    // Verify the input aggregation (a purported previous execution of this program)
    if h_in != Digest::ZERO && d_in != Digest::ZERO {
        env::verify(
            ag_program_key,
            &serde::to_vec(&(ag_program_key, h_in, d_in)).unwrap(),
        )
        .unwrap();
    }

    // Hash-chain the verified output and program.
    //let h_out = aggregation_core::commit_step_output_with_sha(&[h_in], &step_output);
    //let d_out = aggregation_core::commit_step_program_with_sha(&[d_in], &step_program);
    let h_out = arm::hash::commit_step_output_with_sha(&[h_in], &step_output);
    let d_out = arm::hash::commit_step_program_with_sha(&[d_in], &step_program);
    env::commit(&(ag_program_key, h_out, d_out));
}
