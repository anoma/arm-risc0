//! Pins `AggregationInstance::to_journal` (the hand-rolled, zkVM-free
//! encoder in `anoma-rm-core`) to the risc0-serde encoding the batch
//! aggregation guest actually commits. If these ever diverge, an on-chain
//! verifier re-deriving the journal digest from the instance would accept
//! or reject the wrong transactions — this equivalence is load-bearing for
//! every non-zkVM verifier.

use anoma_rm_risc0::aggregation_instance::{
    ActionAggregated, AggregationInstance, AggregationResourceInstance,
};
use anoma_rm_risc0::logic_instance::{AppData, ExpirableBlob};
use anoma_rm_risc0::utils::words_to_bytes;
use anoma_rm_risc0::Digest;

fn risc0_serde_journal(instance: &AggregationInstance) -> Vec<u8> {
    let words = risc0_zkvm::serde::to_vec(instance).expect("risc0-serde encoding succeeds");
    words_to_bytes(&words).to_vec()
}

/// Structurally rich: multiple actions, asymmetric consumed/created counts,
/// a created resource between consumed ones, empty and non-empty payload
/// vectors, empty and multi-word blobs.
fn rich_instance() -> AggregationInstance {
    let blob = |seed: u32, len: usize| ExpirableBlob {
        blob: (0..len as u32).map(|i| seed + i).collect(),
        deletion_criterion: seed % 2,
    };
    AggregationInstance {
        compliance_vk: Digest::from_bytes([0xC0; 32]),
        kind_tree_root: Digest::from_bytes([0xC1; 32]),
        actions: vec![
            ActionAggregated {
                resource_instances: vec![
                    AggregationResourceInstance::Consumed {
                        nullifier: Digest::from_bytes([0x01; 32]),
                        logic_ref: Digest::from_bytes([0x02; 32]),
                        commitment_tree_root: Digest::from_bytes([0x03; 32]),
                        app_data: AppData {
                            resource_payload: vec![blob(100, 3), blob(200, 0)],
                            discovery_payload: vec![],
                            external_payload: vec![blob(300, 1)],
                            application_payload: vec![blob(400, 5)],
                        },
                    },
                    AggregationResourceInstance::Created {
                        commitment: Digest::from_bytes([0x07; 32]),
                        logic_ref: Digest::from_bytes([0x08; 32]),
                        app_data: AppData {
                            resource_payload: vec![],
                            discovery_payload: vec![blob(500, 2)],
                            external_payload: vec![],
                            application_payload: vec![],
                        },
                    },
                    AggregationResourceInstance::Consumed {
                        nullifier: Digest::from_bytes([0x04; 32]),
                        logic_ref: Digest::from_bytes([0x05; 32]),
                        commitment_tree_root: Digest::from_bytes([0x06; 32]),
                        app_data: AppData::new(),
                    },
                ],
                delta_x: [0x11111111; 8],
                delta_y: [0x22222222; 8],
                action_tree_root: Digest::from_bytes([0x09; 32]),
            },
            ActionAggregated {
                resource_instances: vec![],
                delta_x: [0; 8],
                delta_y: [0xFFFFFFFF; 8],
                action_tree_root: Digest::from_bytes([0x0A; 32]),
            },
        ],
    }
}

#[test]
fn aggregation_journal_matches_risc0_serde() {
    let instance = rich_instance();
    assert_eq!(instance.to_journal(), risc0_serde_journal(&instance));
}

#[test]
fn empty_aggregation_journal_matches_risc0_serde() {
    let instance = AggregationInstance {
        compliance_vk: Digest::from_bytes([0xAA; 32]),
        kind_tree_root: Digest::from_bytes([0xBB; 32]),
        actions: vec![],
    };
    assert_eq!(instance.to_journal(), risc0_serde_journal(&instance));
}

/// Borsh encodes enum variants with a u8 discriminant; risc0-serde uses u32.
/// Now that `AggregationResourceInstance` is an enum these two encodings
/// diverge, so non-zkVM verifiers must use `to_journal()` rather than borsh
/// to re-derive the journal digest.
#[test]
fn borsh_encoding_differs_from_aggregation_journal_for_nonempty_actions() {
    let instance = rich_instance();
    assert_ne!(
        borsh::to_vec(&instance).expect("borsh encoding succeeds"),
        instance.to_journal(),
        "borsh and journal encodings must differ now that AggregationResourceInstance is an enum"
    );
}

/// For an instance with no resources, borsh and journal still agree (no
/// enum fields are encoded).
#[test]
fn borsh_encoding_equals_aggregation_journal_for_empty_actions() {
    let instance = AggregationInstance {
        compliance_vk: Digest::from_bytes([0xAA; 32]),
        kind_tree_root: Digest::from_bytes([0xBB; 32]),
        actions: vec![],
    };
    assert_eq!(
        borsh::to_vec(&instance).expect("borsh encoding succeeds"),
        instance.to_journal()
    );
}
