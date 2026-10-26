use anoma_rm_risc0::{
    action_tree::ActionTree,
    aggregation_instance::{ActionAggregated, AggregationInstance, ResourceAggregated},
    aggregation_witness::AggregationWitness,
    logic_instance::LogicInstance,
    merkle_path::PADDING_LEAF,
};
use risc0_zkvm::{guest::env, serde::to_vec, Digest};

fn main() {
    let witness: AggregationWitness = env::read();
    assert!(!witness.actions.is_empty(), "no actions provided");

    let compliance_key = witness.compliance_key;
    // The aggregated kind_tree_root is the shared root across all actions that
    // committed a real kind tree (i.e. any root other than PADDING_LEAF). All
    // such roots must be identical; actions that committed PADDING_LEAF (no kind
    // tree used) are compatible with any root. If every action committed
    // PADDING_LEAF, the aggregated root is also PADDING_LEAF.
    let mut kind_tree_root: Option<Digest> = None;
    let mut actions_out = Vec::with_capacity(witness.actions.len());

    for aw in &witness.actions {
        let ci = &aw.compliance_instance;

        // Serialize the typed compliance instance and verify the proof.
        let ci_words = to_vec(ci).expect("failed to serialize ComplianceInstance");
        env::verify(compliance_key, &ci_words).expect("compliance proof verification failed");

        // Actions that used a kind tree commit a non-PADDING_LEAF root; all
        // such roots must agree. Actions that committed PADDING_LEAF are
        // compatible with any root and do not constrain kind_tree_root.
        if ci.kind_tree_root != PADDING_LEAF {
            let ktr = *kind_tree_root.get_or_insert(ci.kind_tree_root);
            assert_eq!(
                ci.kind_tree_root, ktr,
                "kind_tree_root mismatch across actions"
            );
        }

        assert_eq!(
            aw.app_data.len(),
            ci.resources.len(),
            "resource app_data count mismatch"
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
        //   C – VK   comes from logic_ref in the compliance instance
        let mut resources = Vec::with_capacity(ci.resources.len());
        for (r, app_data) in ci.resources.iter().zip(&aw.app_data) {
            let li = LogicInstance {
                tag: r.tag,
                is_consumed: r.is_consumed(),
                root: action_tree_root,
                app_data: app_data.clone(),
            };
            let li_words = to_vec(&li).expect("failed to serialize LogicInstance");
            env::verify(r.logic_ref, &li_words).expect("logic proof verification failed");
            resources.push(ResourceAggregated {
                consumed: u32::from(r.is_consumed()),
                tag: r.tag,
                logic_ref: r.logic_ref,
                commitment_tree_root: r.commitment_tree_root.unwrap_or(Digest::ZERO),
                app_data: li.app_data,
            });
        }

        actions_out.push(ActionAggregated {
            resources,
            delta_x: ci.delta_x,
            delta_y: ci.delta_y,
            action_tree_root,
        });
    }

    let instance = AggregationInstance {
        compliance_key,
        kind_tree_root: kind_tree_root.unwrap_or(PADDING_LEAF),
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
