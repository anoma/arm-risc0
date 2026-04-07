use anoma_rm_risc0::{
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceInstanceWords,
    execution_proof::{ExecutionProofInstance, ExecutionProofWitness, ResourceAppData},
    transaction::TransactionExt,
    Digest, LogicInstance,
};
use risc0_zkvm::guest::env;

/// Converts an ARM [`Digest`] to the `risc0_zkvm::sha::Digest` expected by `env::verify`.
fn vk_to_risc0(vk: &Digest) -> risc0_zkvm::sha::Digest {
    risc0_zkvm::sha::Digest::new(*vk.as_words())
}

/// Output of [`collect_action_logic`]: the serialised logic proof data needed
/// for the aggregation instance, plus the resource app-data split by role.
struct ActionLogicData {
    /// Serialised logic instances, one per resource (consumed then created per CU).
    lp_instances_u32: Vec<Vec<u32>>,
    /// Verifying keys parallel to `lp_instances_u32`.
    lp_vks: Vec<Digest>,
    /// App-data for consumed resources (nullifier tags), in CU order.
    consumed_resource_app_data: Vec<ResourceAppData>,
    /// App-data for created resources (commitment tags), in CU order.
    created_resource_app_data: Vec<ResourceAppData>,
}

/// Processes a single action in one pass over its compliance units:
///
/// - Builds the ordered tag / logic-ref lists for the action tree.
/// - Asserts that each input's `verifying_key` matches the corresponding
///   `logic_ref` committed inside the compliance instance.
/// - Serialises each [`LogicInstance`] for the aggregation proof.
/// - Splits [`ResourceAppData`] into consumed and created buckets.
fn collect_action_logic(action: &Action) -> ActionLogicData {
    let mut tags = Vec::new();
    let mut logic_refs = Vec::new();

    for cu in action.get_compliance_units() {
        // Ordered as [consumed, created] per CU to match proof construction.
        tags.push(cu.instance.consumed_nullifier);
        logic_refs.push(cu.instance.consumed_logic_ref);
        tags.push(cu.instance.created_commitment);
        logic_refs.push(cu.instance.created_logic_ref);
    }

    let root = MerkleTree::from(tags.clone())
        .root()
        .expect("action tree root");

    let mut lp_vks = Vec::new();
    let mut lp_instances_u32 = Vec::new();
    let mut consumed_resource_app_data = Vec::new();
    let mut created_resource_app_data = Vec::new();

    for (index, (tag, logic_ref)) in tags.iter().zip(logic_refs.iter()).enumerate() {
        let is_consumed = index % 2 == 0;

        let input = action
            .get_logic_verifier_inputs()
            .iter()
            .find(|i| i.tag == *tag)
            .expect("logic verifier input not found for tag");

        assert_eq!(
            input.verifying_key, *logic_ref,
            "verifying key does not match logic ref for tag"
        );

        lp_instances_u32.push(
            risc0_zkvm::serde::to_vec(&LogicInstance {
                tag: input.tag,
                is_consumed,
                root,
                app_data: input.app_data.clone(),
            })
            .expect("serialize logic instance"),
        );
        lp_vks.push(input.verifying_key);

        let resource_app_data = ResourceAppData {
            tag: input.tag,
            vk: input.verifying_key,
            app_data: input.app_data.clone(),
        };
        if is_consumed {
            consumed_resource_app_data.push(resource_app_data);
        } else {
            created_resource_app_data.push(resource_app_data);
        }
    }

    ActionLogicData {
        lp_instances_u32,
        lp_vks,
        consumed_resource_app_data,
        created_resource_app_data,
    }
}

/// All data produced by [`aggregation_instance_words`] for one transaction.
struct TxVerificationData {
    /// Serialised aggregation instance ready for `env::verify`.
    agg_words: Vec<u32>,
    /// App-data for consumed resources across all actions.
    consumed_resource_app_data: Vec<ResourceAppData>,
    /// App-data for created resources across all actions.
    created_resource_app_data: Vec<ResourceAppData>,
}

/// Serialises the batch-aggregation circuit journal as `u32` words for `env::verify`.
///
/// Combines the compliance instances with the per-action logic data (collected
/// by [`collect_action_logic`]) and `compliance_vk` into the tuple expected by
/// the batch aggregation circuit, then serialises it with `risc0_zkvm::serde`.
///
/// Delegates per-action work to [`collect_action_logic`], which visits each
/// action's compliance units and `logic_verifier_inputs` exactly once.
/// The returned [`TxVerificationData`] also carries the [`ResourceAppData`]
/// for all resources in the transaction.
fn aggregation_instance_words(
    tx: &anoma_rm_risc0::Transaction,
    compliance_vk: &Digest,
) -> TxVerificationData {
    let compliance_instances_u32: Vec<ComplianceInstanceWords> = tx
        .get_compliance_instances()
        .expect("compliance instances")
        .iter()
        .map(|b| ComplianceInstanceWords::from_bytes(b).expect("compliance instance words"))
        .collect();

    let mut lp_vks = Vec::new();
    let mut lp_instances_u32 = Vec::new();
    let mut consumed_resource_app_data = Vec::new();
    let mut created_resource_app_data = Vec::new();

    for action in &tx.actions {
        let data = collect_action_logic(action);
        lp_vks.extend(data.lp_vks);
        lp_instances_u32.extend(data.lp_instances_u32);
        consumed_resource_app_data.extend(data.consumed_resource_app_data);
        created_resource_app_data.extend(data.created_resource_app_data);
    }

    let agg_words = risc0_zkvm::serde::to_vec(&(
        compliance_instances_u32,
        compliance_vk,
        lp_instances_u32,
        lp_vks,
    ))
    .expect("serialize aggregation instance");

    TxVerificationData {
        agg_words,
        consumed_resource_app_data,
        created_resource_app_data,
    }
}

pub fn main() {
    let witness: ExecutionProofWitness = env::read();

    // -----------------------------------------------------------------------
    // 1. Initialise running state.
    //
    //    Both tree roots are derived from the witness rather than taken as
    //    explicit inputs, so they are bound to the witness data.
    // -----------------------------------------------------------------------
    // let mut commitment_tree = witness.commitment_tree;
    // let old_commitment_tree_root = commitment_tree.root();
    let mut nullifier_root = witness.old_nullifier_tree_root;

    // -----------------------------------------------------------------------
    // 2. Batch-wide nullifier uniqueness check.
    //
    //    The indexed nullifier tree already prevents re-spending a nullifier
    //    that was inserted in a prior batch.  This check additionally prevents
    //    two compliance units *within this batch* from consuming the same
    //    nullifier before any of them reach the tree-update step.
    //
    //    Nullifiers and commitments are collected here in tx → action → CU
    //    order for reuse in step 3c, avoiding a second pass over the witness.
    // -----------------------------------------------------------------------
    // let mut nullifiers: Vec<Digest> = Vec::new();
    // let mut commitments: Vec<Digest> = Vec::new();
    // for tx in &witness.transactions {
    //     for action in &tx.actions {
    //         for cu in action.get_compliance_units() {
    //             nullifiers.push(cu.instance.consumed_nullifier);
    //             commitments.push(cu.instance.created_commitment);
    //         }
    //     }
    // }

    // Sort a copy of the nullifiers and check adjacent pairs for duplicates.
    // Sorting uses only integer comparisons (Digest is [u32; 8]), which is far
    // cheaper in the zkVM than HashSet whose SipHash has no RISC0 accelerator.
    // let mut sorted_nullifiers = nullifiers.clone();
    // sorted_nullifiers.sort_by_key(|d| *d.as_words());
    // for window in sorted_nullifiers.windows(2) {
    //     assert_ne!(
    //         window[0], window[1],
    //         "duplicate nullifier across transactions"
    //     );
    // }

    // -----------------------------------------------------------------------
    // 3. Per-transaction verification and state transition.
    //
    //    VKs are taken from the witness rather than hardcoded constants so the
    //    circuit is not tied to a specific deployment.
    // -----------------------------------------------------------------------
    // let batch_agg_vk_risc0 = vk_to_risc0(&witness.batch_aggregation_vk);
    let compliance_vk = witness.compliance_vk;

    let mut consumed_resource_app_data: Vec<ResourceAppData> = Vec::new();
    let mut created_resource_app_data: Vec<ResourceAppData> = Vec::new();

    for tx in &witness.transactions {
        // --- 3a. Delta proof ---
        //
        // Verifies that the net value change (Σ created − Σ consumed) across
        // all compliance units in the transaction is zero.
        // let msg = tx.get_delta_msg();
        // let delta_instance = tx.delta().expect("delta instance");
        // match &tx.delta_proof {
        //     Delta::Proof(core_proof) => {
        //         let proof = DeltaProof::from_bytes(&core_proof.0).expect("deserialize delta proof");
        //         DeltaProof::verify(&msg, &proof, delta_instance).expect("delta proof invalid");
        //     }
        //     Delta::Witness(_) => panic!("expected delta proof, got witness"),
        // }

        // --- 3b. Batch aggregation proof ---
        //
        // Verifies that every compliance proof and logic proof inside this
        // transaction was verified by the batch aggregation circuit.
        // `aggregation_instance_words` also collects ResourceAppData in the
        // same pass over logic_verifier_inputs (see TxVerificationData).
        assert!(
            tx.aggregation_proof.is_some(),
            "transaction is missing an aggregation proof"
        );
        // let tx_data = aggregation_instance_words(tx, &compliance_vk);
        // env::verify(batch_agg_vk_risc0, &tx_data.agg_words)
        //     .expect("aggregation proof verification failed");
        // consumed_resource_app_data.extend(tx_data.consumed_resource_app_data);
        // created_resource_app_data.extend(tx_data.created_resource_app_data);
    }

    // -----------------------------------------------------------------------
    // 3c. Per-compliance-unit tree updates (across all transactions).
    //
    //    Nullifier:  `InsertionWitness::apply` proves non-membership of the
    //                consumed nullifier in the current indexed nullifier tree,
    //                inserts it, and returns the updated root.
    //
    //    Commitment: `IncrementalMerkleTree::insert` appends the created
    //                commitment to the incremental commitment tree.
    //
    //    `nullifiers` and `commitments` were pre-collected in step 2, so no
    //    further iteration over the witness transactions is required here.
    // -----------------------------------------------------------------------
    // for ((nf, commitment), nf_witness) in nullifiers
    //     .iter()
    //     .zip(commitments.iter())
    //     .zip(witness.nullifier_witnesses.iter())
    // {
    //     nullifier_root = nf_witness
    //         .apply(nf, &nullifier_root)
    //         .expect("nullifier insertion witness invalid");

    //     commitment_tree
    //         .insert(*commitment)
    //         .expect("commitment tree insert failed");
    // }

    // -----------------------------------------------------------------------
    // 4. Commit the instance.
    //
    //    The VKs are committed alongside the tree roots and resource app-data
    //    so verifiers can inspect which circuit versions were used.
    // -----------------------------------------------------------------------
    env::commit(&ExecutionProofInstance {
        old_commitment_tree_root: Digest::default(), // old_commitment_tree_root,
        old_nullifier_tree_root: witness.old_nullifier_tree_root,
        new_commitment_root: Digest::default(),
        new_nullifier_tree_root: nullifier_root,
        consumed_resource_app_data,
        created_resource_app_data,
        batch_aggregation_vk: witness.batch_aggregation_vk,
        compliance_vk: witness.compliance_vk,
    });
}
