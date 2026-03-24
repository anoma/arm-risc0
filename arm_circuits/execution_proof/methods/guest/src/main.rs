use anoma_rm_risc0::{
    compliance::ComplianceInstanceWords,
    constants::{BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES},
    delta_proof::DeltaProof,
    execution_proof::{ExecutionProofInstance, ExecutionProofWitness},
    merkle_path::{padding_leaf, MerklePathExt},
    transaction::{Delta, TransactionExt},
    utils::bytes_to_words,
    Digest,
};
use risc0_zkvm::guest::env;
use std::collections::HashSet;

/// Converts a 32-byte VK constant to the `risc0_zkvm::sha::Digest` expected by `env::verify`.
fn vk_to_risc0(bytes: &[u8; 32]) -> risc0_zkvm::sha::Digest {
    let words: [u32; 8] = arm_core::utils::bytes_to_words(bytes)
        .try_into()
        .expect("32 bytes always yields 8 words");
    risc0_zkvm::sha::Digest::new(words)
}

/// Builds the aggregation circuit journal as u32 words for use with `env::verify`.
///
/// Replicates `TransactionExt::construct_aggregation_instance` without requiring the
/// host-only `aggregation` feature flag (which pulls in the risc0-zkvm prover).
fn aggregation_instance_words(
    tx: &anoma_rm_risc0::Transaction,
    compliance_vk: &Digest,
) -> Vec<u32> {
    let compliance_instances_u32: Vec<ComplianceInstanceWords> = tx
        .get_compliance_instances()
        .expect("compliance instances")
        .iter()
        .map(|b| ComplianceInstanceWords::from_bytes(b).expect("compliance instance words"))
        .collect();

    let (lp_vks, lp_instances) = tx
        .get_logic_vks_and_instances()
        .expect("logic vks and instances");

    let lp_instances_u32: Vec<Vec<u32>> = lp_instances
        .iter()
        .map(|b| bytes_to_words(b))
        .collect();

    risc0_zkvm::serde::to_vec(&(
        compliance_instances_u32,
        compliance_vk,
        lp_instances_u32,
        lp_vks,
    ))
    .expect("serialize aggregation instance")
}

pub fn main() {
    let witness: ExecutionProofWitness = env::read();

    // -----------------------------------------------------------------------
    // 1. Initialise running tree state from the witness.
    // -----------------------------------------------------------------------
    let mut commitment_tree = witness.commitment_tree;
    let old_commitment_tree_root = commitment_tree.root();
    let mut nullifier_root = witness.old_nullifier_tree_root;
    let empty = padding_leaf();

    // Index into nullifier_paths consumed so far.
    let mut path_idx: usize = 0;

    // -----------------------------------------------------------------------
    // 2. Cross-transaction nullifier deduplication check.
    //
    //    No two transactions in the batch may consume the same nullifier.
    // -----------------------------------------------------------------------
    let mut seen_nullifiers = HashSet::<Digest>::new();
    for tx in &witness.transactions {
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                assert!(
                    seen_nullifiers.insert(cu.instance.consumed_nullifier),
                    "duplicate nullifier across transactions"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Per-transaction verification and state transition.
    // -----------------------------------------------------------------------
    let batch_agg_vk_risc0 = vk_to_risc0(&BATCH_AGGREGATION_VK_BYTES);
    let compliance_vk_core =
        Digest::try_from(COMPLIANCE_VK_BYTES.as_slice()).expect("compliance VK bytes");

    for tx in &witness.transactions {
        // --- 3a. Verify delta proof ---
        let msg = tx.get_delta_msg();
        let delta_instance = tx.delta().expect("delta instance");
        match &tx.delta_proof {
            Delta::Proof(core_proof) => {
                let proof =
                    DeltaProof::from_bytes(&core_proof.0).expect("deserialize delta proof");
                DeltaProof::verify(&msg, &proof, delta_instance).expect("delta proof invalid");
            }
            Delta::Witness(_) => panic!("expected delta proof, got witness"),
        }

        // --- 3b. Verify the batch aggregation proof ---
        //
        // Every transaction submitted to the execution proof circuit must carry
        // a batch aggregation proof.  Individual (non-aggregated) proofs are not
        // accepted; the circuit panics if the field is absent.
        assert!(
            tx.aggregation_proof.is_some(),
            "transaction is missing an aggregation proof"
        );
        let agg_words = aggregation_instance_words(tx, &compliance_vk_core);
        env::verify(batch_agg_vk_risc0, &agg_words)
            .expect("aggregation proof verification failed");

        // --- 3c. Tree updates ---
        //
        // For each compliance unit:
        // 1. Use the nullifier path to prove non-inclusion (the slot currently
        //    holds the empty/padding leaf) and derive the new nullifier root.
        // 2. Insert the created commitment into the incremental tree.
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                let nf = cu.instance.consumed_nullifier;
                let commitment = cu.instance.created_commitment;

                let nf_path = witness
                    .nullifier_paths
                    .get(path_idx)
                    .expect("missing nullifier path");

                // Non-inclusion: the target slot must currently be empty.
                assert_eq!(
                    nf_path.root(&empty),
                    nullifier_root,
                    "nullifier non-inclusion check failed: slot is not empty"
                );

                // Append nullifier: derive new nullifier root.
                nullifier_root = nf_path.root(&nf);

                // Append commitment into the incremental tree.
                commitment_tree
                    .insert(commitment)
                    .expect("commitment tree insert failed");

                path_idx += 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 4. Commit the instance with the updated state.
    // -----------------------------------------------------------------------
    env::commit(&ExecutionProofInstance {
        old_commitment_tree_root,
        old_nullifier_tree_root: witness.old_nullifier_tree_root,
        new_commitment_tree: commitment_tree,
        new_nullifier_tree_root: nullifier_root,
    });
}
