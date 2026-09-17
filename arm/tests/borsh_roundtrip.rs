//! Borsh round-trips for every wire type under the `borsh` feature.
//!
//! The borsh encoding is introduced by this branch (Solana programs consume
//! wire types through Borsh-based tooling); these tests define and pin it:
//! delta proof and witness are fixed-width (65 / 32 bytes, validated on
//! read like the serde path), everything else follows the derives.

use anoma_rm_risc0::aggregation_instance::{
    ActionAggregated, AggregationInstance, ConsumedResourceAggregated, CreatedResourceAggregated,
};
use anoma_rm_risc0::delta_proof::{DeltaProof, DeltaWitness};
use anoma_rm_risc0::logic_instance::{AppData, ExpirableBlob};
use anoma_rm_risc0::transaction::{Aggregation, Delta, Transaction};
use anoma_rm_risc0::Digest;

fn roundtrip<T>(value: &T) -> T
where
    T: borsh::BorshSerialize + borsh::BorshDeserialize,
{
    let bytes = borsh::to_vec(value).expect("borsh serialize");
    borsh::from_slice(&bytes).expect("borsh deserialize")
}

fn witness() -> DeltaWitness {
    DeltaWitness::from_bytes(&[0x11; 32]).expect("fixed scalar is in range")
}

fn proof() -> DeltaProof {
    anoma_rm_risc0::delta_proof::prove(b"borsh roundtrip message", &witness())
        .expect("deterministic proving succeeds")
}

fn instance() -> AggregationInstance {
    AggregationInstance {
        compliance_key: Digest::from_bytes([0xC0; 32]),
        kind_table_commitment: Digest::from_bytes([0xC1; 32]),
        actions: vec![ActionAggregated {
            consumed_publics: vec![ConsumedResourceAggregated {
                resource_nullifier: Digest::from_bytes([0x01; 32]),
                resource_logic_ref: Digest::from_bytes([0x02; 32]),
                commitment_tree_root: Digest::from_bytes([0x03; 32]),
                app_data: AppData {
                    resource_payload: vec![ExpirableBlob {
                        blob: vec![1, 2, 3],
                        deletion_criterion: 1,
                    }],
                    discovery_payload: vec![],
                    external_payload: vec![ExpirableBlob {
                        blob: vec![],
                        deletion_criterion: 0,
                    }],
                    application_payload: vec![],
                },
            }],
            created_publics: vec![CreatedResourceAggregated {
                resource_commitment: Digest::from_bytes([0x04; 32]),
                resource_logic_ref: Digest::from_bytes([0x05; 32]),
                app_data: AppData::new(),
            }],
            delta_x: [0x11111111; 8],
            delta_y: [0x22222222; 8],
            action_tree_root: Digest::from_bytes([0x06; 32]),
        }],
    }
}

#[test]
fn delta_types_roundtrip_and_are_fixed_width() {
    let p = proof();
    let bytes = borsh::to_vec(&p).unwrap();
    assert_eq!(bytes.len(), 65, "proof is a raw 65-byte encoding");
    assert_eq!(bytes, p.to_bytes());
    assert_eq!(roundtrip(&p), p);

    let w = witness();
    let bytes = borsh::to_vec(&w).unwrap();
    assert_eq!(bytes.len(), 32, "witness is a raw 32-byte encoding");
    assert_eq!(bytes, w.to_bytes());
    assert_eq!(roundtrip(&w), w);
}

#[test]
fn delta_borsh_validates_on_read() {
    // recovery byte outside {0,1,27,28} must fail
    let mut bad = proof().to_bytes();
    bad[64] = 5;
    assert!(borsh::from_slice::<DeltaProof>(&bad).is_err());

    // out-of-range witness scalar must fail
    let zero = [0u8; 32];
    assert!(borsh::from_slice::<DeltaWitness>(&zero).is_err());
}

#[test]
fn aggregated_transaction_roundtrips() {
    let tx = Transaction {
        actions: None,
        delta_proof: Delta::Proof(proof()),
        expected_balance: None,
        aggregation: Some(Aggregation {
            proof: vec![0xAB; 40],
            instance: instance(),
        }),
    };
    assert_eq!(roundtrip(&tx), tx);
}

#[test]
fn unaggregated_transaction_roundtrips() {
    let tx = Transaction {
        actions: Some(vec![]),
        delta_proof: Delta::Witness(witness()),
        expected_balance: None,
        aggregation: None,
    };
    assert_eq!(roundtrip(&tx), tx);
}

#[test]
fn aggregation_instance_roundtrips() {
    let inst = instance();
    assert_eq!(roundtrip(&inst), inst);
}
