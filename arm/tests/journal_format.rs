//! Wire-format pinning tests.
//!
//! The aggregation journal byte format is part of the protocol — external
//! verifiers (e.g. the Solana protocol adapter's on-chain program)
//! reconstruct it to bind the Groth16 public input. These tests lock the
//! hand-rolled `AggregationInstance::to_journal` encoder against
//! `risc0_zkvm::serde::to_vec`, which is what the batch aggregation guest
//! emits via `env::commit`. If risc0's serde ever changes its encoding of
//! this shape, these tests fail and the codec must be updated deliberately
//! (with coordinated fixture regeneration and cross-adapter parity).
//!
//! The borsh round-trip tests pin the borsh-encoded transaction wire format
//! that on-chain consumers deserialize.

use anoma_rm_risc0::{action::Action, utils::words_to_bytes};
use anoma_rm_risc0::{
    aggregation_instance::{
        ActionAggregated, AggregationInstance, ConsumedResourceAggregated,
        CreatedResourceAggregated,
    },
    compliance_unit::ComplianceUnit,
    delta_proof::{DeltaProof, DeltaWitness},
    logic_instance::{AppData, ExpirableBlob},
    logic_proof::LogicVerifierInput,
    transaction::{Aggregation, Delta, Transaction},
    Digest,
};
use risc0_zkvm::serde::to_vec;

fn digest(byte: u8) -> Digest {
    Digest::from([byte; 32])
}

fn rich_app_data() -> AppData {
    AppData {
        resource_payload: vec![ExpirableBlob {
            blob: vec![0xDEAD_BEEF, 0xCAFE_BABE],
            deletion_criterion: 7,
        }],
        discovery_payload: vec![ExpirableBlob {
            blob: vec![],
            deletion_criterion: 0,
        }],
        external_payload: vec![
            ExpirableBlob {
                blob: vec![0x1111_2222],
                deletion_criterion: 1,
            },
            ExpirableBlob {
                blob: vec![1, 2, 3, 4, 5],
                deletion_criterion: 2,
            },
        ],
        application_payload: vec![],
    }
}

fn sample_instance() -> AggregationInstance {
    AggregationInstance {
        compliance_key: digest(0x01),
        kind_table_commitment: digest(0x02),
        actions: vec![
            ActionAggregated {
                consumed_publics: vec![
                    ConsumedResourceAggregated {
                        resource_nullifier: digest(0x03),
                        resource_logic_ref: digest(0x04),
                        commitment_tree_root: digest(0x05),
                        app_data: rich_app_data(),
                    },
                    ConsumedResourceAggregated {
                        resource_nullifier: digest(0x06),
                        resource_logic_ref: digest(0x07),
                        commitment_tree_root: digest(0x08),
                        app_data: AppData::new(),
                    },
                ],
                created_publics: vec![CreatedResourceAggregated {
                    resource_commitment: digest(0x09),
                    resource_logic_ref: digest(0x0A),
                    app_data: rich_app_data(),
                }],
                delta_x: [0xAAAA_0001; 8],
                delta_y: [0xBBBB_0001; 8],
                action_tree_root: digest(0x0B),
            },
            ActionAggregated {
                consumed_publics: vec![],
                created_publics: vec![CreatedResourceAggregated {
                    resource_commitment: digest(0x0C),
                    resource_logic_ref: digest(0x0D),
                    app_data: AppData::new(),
                }],
                delta_x: [0xCCCC_0001; 8],
                delta_y: [0xDDDD_0001; 8],
                action_tree_root: digest(0x0E),
            },
        ],
    }
}

/// The batch aggregation guest commits an `AggregationInstance` via
/// `env::commit` (risc0 serde). `to_journal` must re-derive those exact
/// bytes, over a structurally rich instance: multiple actions, uneven
/// consumed/created counts, and app data covering all four payload
/// categories with empty and non-empty blobs.
#[test]
fn aggregation_journal_matches_risc0_serde() {
    let instance = sample_instance();
    assert_eq!(
        instance.to_journal(),
        words_to_bytes(&to_vec(&instance).unwrap()).to_vec(),
    );
}

/// Empty-actions variant locks the u32 little-endian length-prefix encoding.
#[test]
fn aggregation_journal_empty_actions_matches_risc0_serde() {
    let instance = AggregationInstance {
        compliance_key: Digest::default(),
        kind_table_commitment: Digest::default(),
        actions: vec![],
    };
    assert_eq!(
        instance.to_journal(),
        words_to_bytes(&to_vec(&instance).unwrap()).to_vec(),
    );
}

/// `delta_msg` is the concatenation of the action tree roots, in order.
#[test]
fn delta_msg_is_concatenated_roots() {
    let instance = sample_instance();
    let expected: Vec<u8> = instance
        .actions
        .iter()
        .flat_map(|a| a.action_tree_root.as_bytes().to_vec())
        .collect();
    assert_eq!(instance.delta_msg(), expected);
}

fn sample_delta_proof() -> DeltaProof {
    use k256_test_support::signed_proof;
    signed_proof()
}

/// k256 helpers for building a structurally valid delta proof in tests.
mod k256_test_support {
    use anoma_rm_risc0::delta_proof::{DeltaProof, DeltaWitness};

    pub fn witness() -> DeltaWitness {
        DeltaWitness::from_bytes(&[7u8; 32]).unwrap()
    }

    pub fn signed_proof() -> DeltaProof {
        // A deterministic signature over a fixed prehash-sized message,
        // exercising the {27,28} v-byte wire encoding.
        DeltaProof::prove(b"borsh-wire-pin", &witness()).unwrap()
    }
}

/// Borsh round-trip of an aggregated wire transaction — the shape on-chain
/// consumers deserialize.
#[test]
fn borsh_roundtrip_aggregated_transaction() {
    let tx = Transaction {
        actions: None,
        delta_proof: Delta::Proof(sample_delta_proof()),
        expected_balance: None,
        aggregation: Some(Aggregation {
            proof: vec![1, 2, 3, 4],
            instance: sample_instance(),
        }),
    };

    let encoded = borsh::to_vec(&tx).unwrap();
    let decoded: Transaction = borsh::from_slice(&encoded).unwrap();
    assert_eq!(tx, decoded);
}

/// Borsh round-trip of an unaggregated transaction carrying actions and a
/// delta witness.
#[test]
fn borsh_roundtrip_actions_transaction() {
    let action = Action {
        compliance_unit: ComplianceUnit {
            proof: vec![9, 9, 9],
            instance: vec![8; 16],
        },
        logic_verifier_inputs: vec![LogicVerifierInput {
            tag: digest(0x21),
            verifying_key: digest(0x22),
            app_data: rich_app_data(),
            proof: vec![5, 6, 7],
        }],
    };
    let tx = Transaction {
        actions: Some(vec![action]),
        delta_proof: Delta::Witness(k256_test_support::witness()),
        expected_balance: Some(vec![0; 4]),
        aggregation: None,
    };

    let encoded = borsh::to_vec(&tx).unwrap();
    let decoded: Transaction = borsh::from_slice(&encoded).unwrap();
    assert_eq!(tx, decoded);
}

/// The borsh encoding of the delta types is their byte-level wire form:
/// 65 bytes ({27,28} v-byte) for the proof, 32 bytes for the witness.
#[test]
fn borsh_delta_types_are_fixed_width_bytes() {
    let proof = sample_delta_proof();
    let encoded = borsh::to_vec(&proof).unwrap();
    assert_eq!(encoded.len(), 65);
    assert_eq!(encoded, proof.to_bytes().to_vec());
    assert!(encoded[64] == 27 || encoded[64] == 28);

    let witness = k256_test_support::witness();
    let encoded = borsh::to_vec(&witness).unwrap();
    assert_eq!(encoded.len(), 32);
    assert_eq!(encoded, witness.to_bytes().to_vec());

    let decoded: DeltaWitness = borsh::from_slice(&encoded).unwrap();
    assert_eq!(decoded, witness);
}
