use anoma_rm_risc0::{
    action_tree::MerkleTree,
    compliance::{ComplianceInstanceExt, ComplianceInstanceWords},
    execution_proof::{
        ActionInfo, ActionInput, ExecutionProofInstance, ExecutionProofWitness, ResourceAppData,
        TxInfo,
    },
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
    /// The action tree root derived from the compliance instances.
    action_root: Digest,
    /// App-data for consumed resources (nullifier tags), in CU order.
    consumed_resource_app_data: Vec<ResourceAppData>,
    /// App-data for created resources (commitment tags), in CU order.
    created_resource_app_data: Vec<ResourceAppData>,
}

/// Processes a single action's compliance instances and logic verifier inputs:
///
/// - Builds the action tree and derives its root (one pass over CUs for tags).
/// - Asserts that each input's `verifying_key` matches the corresponding
///   `logic_ref` committed inside the compliance instance.
/// - Serialises each [`LogicInstance`] for the aggregation proof.
/// - Splits [`ResourceAppData`] into consumed and created buckets.
fn collect_action_logic(action: &ActionInput) -> ActionLogicData {
    let n = action.compliance_instances.len();

    // Pass 1: build tree tags (2 per CU) and compute the action tree root.
    let tree_tags: Vec<Digest> = action
        .compliance_instances
        .iter()
        .flat_map(|ci| [ci.consumed_nullifier, ci.created_commitment])
        .collect();
    let root = MerkleTree::from(tree_tags)
        .root()
        .expect("action tree root");

    // Pass 2: process logic verifier inputs for each (tag, logic_ref) pair.
    let mut lp_vks = Vec::with_capacity(2 * n);
    let mut lp_instances_u32 = Vec::with_capacity(2 * n);
    let mut consumed_resource_app_data = Vec::with_capacity(n);
    let mut created_resource_app_data = Vec::with_capacity(n);

    for ci in &action.compliance_instances {
        for (tag, logic_ref, is_consumed) in [
            (ci.consumed_nullifier, ci.consumed_logic_ref, true),
            (ci.created_commitment, ci.created_logic_ref, false),
        ] {
            let input = action
                .logic_verifier_inputs
                .iter()
                .find(|i| i.tag == tag)
                .expect("logic verifier input not found for tag");

            assert_eq!(
                input.verifying_key, logic_ref,
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
    }

    ActionLogicData {
        lp_instances_u32,
        lp_vks,
        action_root: root,
        consumed_resource_app_data,
        created_resource_app_data,
    }
}

/// All data produced by [`aggregation_instance_words`] for one transaction.
struct TxVerificationData {
    /// Serialised aggregation instance ready for `env::verify`.
    agg_words: Vec<u32>,
    /// Structured per-action output; delta data is added by the caller.
    action_infos: Vec<ActionInfo>,
}

/// Serialises the batch-aggregation circuit journal as `u32` words for `env::verify`.
///
/// Combines the compliance instances (derived directly from [`ActionInput`])
/// with the per-action logic data (collected by [`collect_action_logic`]) and
/// `compliance_vk` into the tuple expected by the batch aggregation circuit,
/// then serialises it with `risc0_zkvm::serde`.
///
/// Delegates per-action work to [`collect_action_logic`], which visits each
/// action's compliance instances and logic verifier inputs exactly once.
/// The returned [`TxVerificationData`] also carries the [`ResourceAppData`]
/// for all resources in the transaction.
fn aggregation_instance_words(
    tx: &anoma_rm_risc0::execution_proof::TxInput,
    compliance_vk: &Digest,
) -> TxVerificationData {
    // Build compliance instance words directly from the ActionInput structs —
    // no journal byte parsing needed.
    let compliance_instances_u32: Vec<ComplianceInstanceWords> = tx
        .actions
        .iter()
        .flat_map(|a| a.compliance_instances.iter())
        .map(ComplianceInstanceWords::from)
        .collect();

    let total_cus: usize = tx
        .actions
        .iter()
        .map(|a| a.compliance_instances.len())
        .sum();
    let mut lp_vks = Vec::with_capacity(2 * total_cus);
    let mut lp_instances_u32 = Vec::with_capacity(2 * total_cus);
    let mut action_infos = Vec::with_capacity(tx.actions.len());

    for action in &tx.actions {
        let data = collect_action_logic(action);
        lp_vks.extend(data.lp_vks);
        lp_instances_u32.extend(data.lp_instances_u32);
        action_infos.push(ActionInfo {
            action_tree_root: data.action_root,
            consumed_resource_app_data: data.consumed_resource_app_data,
            created_resource_app_data: data.created_resource_app_data,
        });
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
        action_infos,
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
    let mut commitment_tree = witness.commitment_tree;
    let old_commitment_tree_root = commitment_tree.root();
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
    let total_cus: usize = witness
        .transactions
        .iter()
        .flat_map(|tx| tx.actions.iter())
        .map(|a| a.compliance_instances.len())
        .sum();
    let mut nullifiers: Vec<Digest> = Vec::with_capacity(total_cus);
    let mut commitments: Vec<Digest> = Vec::with_capacity(total_cus);
    for tx in &witness.transactions {
        for action in &tx.actions {
            for ci in &action.compliance_instances {
                nullifiers.push(ci.consumed_nullifier);
                commitments.push(ci.created_commitment);
            }
        }
    }

    // Sort a copy of the nullifiers and check adjacent pairs for duplicates.
    // Sorting uses only integer comparisons (Digest is [u32; 8]), which is far
    // cheaper in the zkVM than HashSet whose SipHash has no RISC0 accelerator.
    // The copy is necessary because `nullifiers` must stay in original order
    // for zipping with `nullifier_witnesses` in step 3c.
    let mut sorted_nullifiers = nullifiers.clone();
    sorted_nullifiers.sort_unstable_by_key(|d| *d.as_words());
    for window in sorted_nullifiers.windows(2) {
        assert_ne!(
            window[0], window[1],
            "duplicate nullifier across transactions"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Per-transaction verification and state transition.
    //
    //    VKs are taken from the witness rather than hardcoded constants so the
    //    circuit is not tied to a specific deployment.
    // -----------------------------------------------------------------------
    let batch_agg_vk_risc0 = vk_to_risc0(&witness.batch_aggregation_vk);
    let compliance_vk = witness.compliance_vk;

    let mut tx_infos: Vec<TxInfo> = Vec::with_capacity(witness.transactions.len());

    for tx in &witness.transactions {
        // --- 3a. Delta proof (pass-through) ---
        //
        // The delta proof is not verified inside the zkVM — ECDSA recovery is
        // the dominant cost (~62% of total cycles).  The raw proof bytes are
        // committed to the journal so an external verifier can check the
        // signature against the delta message they reconstruct from the
        // committed nullifiers and commitments.

        // --- 3b. Batch aggregation proof ---
        //
        // Verifies that every compliance proof and logic proof inside this
        // transaction was verified by the batch aggregation circuit.
        // `aggregation_instance_words` also collects ResourceAppData in the
        // same pass over logic_verifier_inputs (see TxVerificationData).
        //
        // Note: `aggregation_proof` is host-only (`#[serde(skip)]`) so it is
        // always empty in the guest; the corresponding InnerReceipt was
        // registered as an assumption by the host and is resolved here by
        // `env::verify`.
        let tx_data = aggregation_instance_words(tx, &compliance_vk);
        env::verify(batch_agg_vk_risc0, &tx_data.agg_words)
            .expect("aggregation proof verification failed");
        tx_infos.push(TxInfo {
            action_infos: tx_data.action_infos,
            delta_proof: tx.delta_proof.clone(),
        });
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
    for ((nf, commitment), nf_witness) in nullifiers
        .iter()
        .zip(commitments.iter())
        .zip(witness.nullifier_witnesses.iter())
    {
        nullifier_root = nf_witness
            .apply(nf, &nullifier_root)
            .expect("nullifier insertion witness invalid");

        commitment_tree
            .insert(*commitment)
            .expect("commitment tree insert failed");
    }

    // -----------------------------------------------------------------------
    // 4. Commit the instance.
    //
    //    The VKs are committed alongside the tree roots and resource app-data
    //    so verifiers can inspect which circuit versions were used.
    // -----------------------------------------------------------------------
    env::commit(&ExecutionProofInstance {
        old_commitment_tree_root,
        old_nullifier_tree_root: witness.old_nullifier_tree_root,
        new_commitment_root: commitment_tree.root(),
        new_nullifier_tree_root: nullifier_root,
        tx_infos,
        batch_aggregation_vk: witness.batch_aggregation_vk,
        compliance_vk: witness.compliance_vk,
    });
}
