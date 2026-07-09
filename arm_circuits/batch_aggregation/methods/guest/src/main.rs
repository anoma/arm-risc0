use anoma_rm_risc0::{
    action_tree::ActionTree,
    aggregation_instance::{
        ActionAggregated, AggregationInstance, ConsumedResourceAggregated,
        CreatedResourceAggregated,
    },
    compliance::ComplianceInstance,
    logic_instance::LogicInstance,
    resource::{ConsumedResourcePublic, CreatedResourcePublic},
};
use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;

fn main() {
    // Read raw inputs (same API as before — no prover-side change).
    let compliance_instances_raw: Vec<Vec<u32>> = env::read();
    let compliance_key: Digest = env::read();
    let logic_instances_raw: Vec<Vec<u32>> = env::read();
    let logic_keys: Vec<Digest> = env::read();

    assert_eq!(
        logic_instances_raw.len(),
        logic_keys.len(),
        "Mismatched logic instances and keys lengths"
    );

    // Step 1 — Verify every proof (unchanged behaviour).
    for ci in &compliance_instances_raw {
        env::verify(compliance_key, ci).expect("compliance proof verification failed");
    }
    for (li, lk) in logic_instances_raw.iter().zip(&logic_keys) {
        env::verify(*lk, li).expect("logic proof verification failed");
    }

    // Step 2 — Deserialize into typed structs.
    let compliance_instances: Vec<ComplianceInstance> = compliance_instances_raw
        .iter()
        .map(|w| {
            risc0_zkvm::serde::from_slice(w).expect("failed to deserialize ComplianceInstance")
        })
        .collect();

    let logic_instances: Vec<LogicInstance> = logic_instances_raw
        .iter()
        .map(|w| risc0_zkvm::serde::from_slice(w).expect("failed to deserialize LogicInstance"))
        .collect();

    // Step 3 — Positional iterator: the prover must supply logic_instances in
    // the same canonical order as tags appear across compliance instances
    // (consumed nullifiers then created commitments, action by action).
    let mut li_iter = logic_instances.iter().zip(logic_keys.iter());

    // Step 4 — Assert shared kind_table_commitment.
    assert!(
        !compliance_instances.is_empty(),
        "No compliance instances supplied"
    );
    let kind_table_commitment = compliance_instances[0].kind_table_commitment;
    for ci in &compliance_instances {
        assert_eq!(
            ci.kind_table_commitment, kind_table_commitment,
            "kind_table_commitment mismatch across actions"
        );
    }

    // Step 5 — Cross-check per action and build the compact structs.
    let mut actions = Vec::with_capacity(compliance_instances.len());

    for ci in &compliance_instances {
        // Recompute the action tree root from the compliance tags (never
        // trusted from the prover; always derived inside the guest).
        let tags: Vec<Digest> = ci.tags().collect();
        let action_tree_root = ActionTree::new(tags)
            .root()
            .expect("action tree root computation failed");

        let mut consumed_publics = Vec::with_capacity(ci.consumed_publics.len());
        for r in &ci.consumed_publics {
            let (li, lk) = li_iter
                .next()
                .expect("fewer logic instances than compliance tags (prover ordering violation)");
            consumed_publics.push(check_consumed(r, li, lk, action_tree_root));
        }

        let mut created_publics = Vec::with_capacity(ci.created_publics.len());
        for r in &ci.created_publics {
            let (li, lk) = li_iter
                .next()
                .expect("fewer logic instances than compliance tags (prover ordering violation)");
            created_publics.push(check_created(r, li, lk, action_tree_root));
        }

        actions.push(ActionAggregated {
            consumed_publics,
            created_publics,
            delta_x: ci.delta_x,
            delta_y: ci.delta_y,
            action_tree_root,
        });
    }

    // Assert no surplus logic instances were supplied.
    assert!(
        li_iter.next().is_none(),
        "more logic instances than compliance tags"
    );

    // Step 6 — Commit the compact AggregationInstance (not the raw blobs).
    env::commit(&AggregationInstance {
        compliance_key,
        kind_table_commitment,
        actions,
    });
}

/// Enforces constraints A–C for a consumed resource and returns the aggregated struct.
fn check_consumed(
    r: &ConsumedResourcePublic,
    li: &LogicInstance,
    lk: &Digest,
    action_tree_root: Digest,
) -> ConsumedResourceAggregated {
    // Constraint A: positional tag must match the compliance nullifier.
    assert_eq!(li.tag, r.resource_nullifier, "tag mismatch (consumed)");
    // Constraint B: logic circuit ran against the same action tree.
    assert_eq!(li.root, action_tree_root, "root mismatch (consumed)");
    // Constraint C: verifying key matches the declared logic ref.
    assert_eq!(*lk, r.resource_logic_ref, "VK mismatch (consumed)");
    ConsumedResourceAggregated {
        resource_nullifier: r.resource_nullifier,
        resource_logic_ref: r.resource_logic_ref,
        commitment_tree_root: r.commitment_tree_root,
        app_data: li.app_data.clone(),
    }
}

/// Enforces constraints A–C for a created resource and returns the aggregated struct.
fn check_created(
    r: &CreatedResourcePublic,
    li: &LogicInstance,
    lk: &Digest,
    action_tree_root: Digest,
) -> CreatedResourceAggregated {
    // Constraint A: positional tag must match the compliance commitment.
    assert_eq!(li.tag, r.resource_commitment, "tag mismatch (created)");
    // Constraint B: logic circuit ran against the same action tree.
    assert_eq!(li.root, action_tree_root, "root mismatch (created)");
    // Constraint C: verifying key matches the declared logic ref.
    assert_eq!(*lk, r.resource_logic_ref, "VK mismatch (created)");
    CreatedResourceAggregated {
        resource_commitment: r.resource_commitment,
        resource_logic_ref: r.resource_logic_ref,
        app_data: li.app_data.clone(),
    }
}
