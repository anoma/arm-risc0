use anoma_rm_risc0::{
    action_tree::ActionTree,
    aggregation_instance::{
        ActionAggregated, AggregationInstance, ConsumedResourceAggregated,
        CreatedResourceAggregated,
    },
    aggregation_witness::AggregationWitness,
    logic_instance::LogicInstance,
};
use risc0_zkvm::{guest::env, serde::to_vec, Digest};

fn main() {
    let witness: AggregationWitness = env::read();
    assert!(!witness.actions.is_empty(), "no actions provided");

    let compliance_key = witness.compliance_key;
    let mut kind_table_commitment: Option<Digest> = None;
    let mut actions_out = Vec::with_capacity(witness.actions.len());

    for aw in &witness.actions {
        let ci = &aw.compliance_instance;

        // Serialize the typed compliance instance and verify the proof.
        let ci_words = to_vec(ci).expect("failed to serialize ComplianceInstance");
        env::verify(compliance_key, &ci_words).expect("compliance proof verification failed");

        // All actions must share the same kind_table_commitment.
        let ktc = *kind_table_commitment.get_or_insert(ci.kind_table_commitment);
        assert_eq!(
            ci.kind_table_commitment, ktc,
            "kind_table_commitment mismatch across actions"
        );

        assert_eq!(
            aw.consumed_app_data.len(),
            ci.consumed_publics.len(),
            "consumed app_data count mismatch"
        );
        assert_eq!(
            aw.created_app_data.len(),
            ci.created_publics.len(),
            "created app_data count mismatch"
        );

        // Recompute the action tree root from the compliance tags — never trusted from the prover.
        let tags: Vec<Digest> = ci.tags().collect();
        let action_tree_root = ActionTree::new(tags)
            .root()
            .expect("action tree root computation failed");

        // For each resource, construct the LogicInstance from context and the provided app_data,
        // serialize it, then verify the logic proof. Constraints A/B/C are enforced structurally:
        //   A – tag  comes from the compliance nullifier/commitment
        //   B – root comes from the in-circuit recomputed action_tree_root
        //   C – VK   comes from resource_logic_ref in the compliance instance
        let mut consumed_publics = Vec::with_capacity(ci.consumed_publics.len());
        for (r, app_data) in ci.consumed_publics.iter().zip(&aw.consumed_app_data) {
            let li = LogicInstance {
                tag: r.resource_nullifier,
                is_consumed: true,
                root: action_tree_root,
                app_data: app_data.clone(),
            };
            let li_words = to_vec(&li).expect("failed to serialize LogicInstance");
            env::verify(r.resource_logic_ref, &li_words)
                .expect("logic proof verification failed (consumed)");
            consumed_publics.push(ConsumedResourceAggregated {
                resource_nullifier: r.resource_nullifier,
                resource_logic_ref: r.resource_logic_ref,
                commitment_tree_root: r.commitment_tree_root,
                app_data: li.app_data,
            });
        }

        let mut created_publics = Vec::with_capacity(ci.created_publics.len());
        for (r, app_data) in ci.created_publics.iter().zip(&aw.created_app_data) {
            let li = LogicInstance {
                tag: r.resource_commitment,
                is_consumed: false,
                root: action_tree_root,
                app_data: app_data.clone(),
            };
            let li_words = to_vec(&li).expect("failed to serialize LogicInstance");
            env::verify(r.resource_logic_ref, &li_words)
                .expect("logic proof verification failed (created)");
            created_publics.push(CreatedResourceAggregated {
                resource_commitment: r.resource_commitment,
                resource_logic_ref: r.resource_logic_ref,
                app_data: li.app_data,
            });
        }

        actions_out.push(ActionAggregated {
            consumed_publics,
            created_publics,
            delta_x: ci.delta_x,
            delta_y: ci.delta_y,
            action_tree_root,
        });
    }

    let instance = AggregationInstance {
        compliance_key,
        kind_table_commitment: kind_table_commitment.unwrap(),
        actions: actions_out,
    };

    #[cfg(feature = "abi_encoding")]
    {
        use anoma_rm_risc0::aggregation_instance::abi_encode_instance;
        env::commit_slice(&abi_encode_instance(instance));
    }

    #[cfg(not(feature = "abi_encoding"))]
    env::commit(&instance);
}
