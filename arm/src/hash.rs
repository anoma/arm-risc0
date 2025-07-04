use risc0_zkvm::sha::{Impl, Sha256, DIGEST_BYTES};
use risc0_zkvm::Digest;

pub fn commit_step_output_with_sha(prev_hashes: &[Digest], step_output_serde: &[u32]) -> Digest {
    let step_output_bytes: Vec<u8> = step_output_serde
        .iter()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    sha_digest(&flatten_prev_hashes(prev_hashes), &step_output_bytes)
}

pub fn commit_step_program_with_sha(prev_hashes: &[Digest], step_program: &Digest) -> Digest {
    sha_digest(&flatten_prev_hashes(prev_hashes), step_program.as_bytes())
}

fn sha_digest(prev_hashes: &[u8], tip: &[u8]) -> Digest {
    let prev_hashes_length: usize = prev_hashes.len();
    let tip_length: usize = tip.len();
    let mut bytes = vec![0u8; tip_length + prev_hashes_length];
    bytes[0..tip_length].clone_from_slice(tip);
    bytes[tip_length..tip_length + prev_hashes_length].clone_from_slice(prev_hashes);

    *Impl::hash_bytes(&bytes)
}

fn flatten_prev_hashes(prev_hashes: &[Digest]) -> Vec<u8> {
    let mut prev_hashes_bytes = vec![0u8; DIGEST_BYTES * prev_hashes.len()];
    let mut offset: usize = 0;
    for h in prev_hashes {
        prev_hashes_bytes[offset..offset + DIGEST_BYTES].clone_from_slice(h.as_bytes());
        offset += DIGEST_BYTES;
    }

    prev_hashes_bytes
}
