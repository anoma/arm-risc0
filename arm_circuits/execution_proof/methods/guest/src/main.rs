use anoma_rm_risc0::{
    compliance::ComplianceInstanceWords,
    constants::{BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES},
    delta_proof::DeltaProof,
    execution_proof::{ExecutionProofInstance, ExecutionProofWitness},
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

/// Serialises the batch-aggregation circuit journal as `u32` words for `env::verify`.
///
/// Replicates `TransactionExt::construct_aggregation_instance` without
/// requiring the host-only `aggregation` feature flag (which pulls in the
/// RISC0 prover stack).
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
    // 1. Initialise running state.
    //
    //    Both tree roots are derived from the witness rather than taken as
    //    explicit inputs, so they are bound to the witness data.
    // -----------------------------------------------------------------------
    let mut commitment_tree = witness.commitment_tree;
    let old_commitment_tree_root = commitment_tree.root();
    let mut nullifier_root = witness.old_nullifier_tree_root;

    // Flat cursor into `witness.nullifier_witnesses`, advanced once per
    // compliance unit across all transactions and actions.
    let mut nullifier_witness_idx: usize = 0;

    // -----------------------------------------------------------------------
    // 2. Batch-wide nullifier uniqueness check.
    //
    //    The indexed nullifier tree already prevents re-spending a nullifier
    //    that was inserted in a prior batch.  This check additionally prevents
    //    two compliance units *within this batch* from consuming the same
    //    nullifier before any of them reach the tree-update step.
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
        // --- 3a. Delta proof ---
        //
        // Verifies that the net value change (Σ created − Σ consumed) across
        // all compliance units in the transaction is zero.
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

        // --- 3b. Batch aggregation proof ---
        //
        // Confirms that every compliance proof and logic proof inside this
        // transaction has been verified by the batch aggregation circuit.
        // Transactions without an aggregation proof are rejected.
        assert!(
            tx.aggregation_proof.is_some(),
            "transaction is missing an aggregation proof"
        );
        let agg_words = aggregation_instance_words(tx, &compliance_vk_core);
        env::verify(batch_agg_vk_risc0, &agg_words)
            .expect("aggregation proof verification failed");

        // --- 3c. Per-compliance-unit tree updates ---
        //
        // For each compliance unit, in order:
        //
        // Nullifier:  `InsertionWitness::apply` proves that `consumed_nullifier`
        //             is not yet in the indexed nullifier tree (non-membership),
        //             inserts it, and returns the new nullifier root.
        //
        // Commitment: `IncrementalMerkleTree::insert` appends `created_commitment`
        //             to the incremental commitment tree.
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                let nf = cu.instance.consumed_nullifier;
                let commitment = cu.instance.created_commitment;

                let nf_witness = witness
                    .nullifier_witnesses
                    .get(nullifier_witness_idx)
                    .expect("missing nullifier insertion witness");

                nullifier_root = nf_witness
                    .apply(&nf, &nullifier_root)
                    .expect("nullifier insertion witness invalid");

                commitment_tree
                    .insert(commitment)
                    .expect("commitment tree insert failed");

                nullifier_witness_idx += 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 4. Commit the instance.
    // -----------------------------------------------------------------------
    env::commit(&ExecutionProofInstance {
        old_commitment_tree_root,
        old_nullifier_tree_root: witness.old_nullifier_tree_root,
        new_commitment_root: commitment_tree.root(),
        new_nullifier_tree_root: nullifier_root,
    });
}
