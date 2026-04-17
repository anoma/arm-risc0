//! ARM Journal v1 format pinning tests.
//!
//! The ARM journal byte format is part of the protocol — both the Solana PA
//! and the EVM PA reconstruct it on-chain to verify aggregation proofs. These
//! tests lock the format against `risc0_zkvm::serde::to_vec`, which is what
//! circuit guests emit via `env::commit`. If risc0_zkvm::serde ever changes
//! its encoding of these shapes, these tests will fail and the protocol
//! codec must be updated deliberately (with coordinated fixture regeneration
//! and cross-adapter parity).
//!
//! Isolated from library source: pure public-API integration tests.

use anoma_rm_risc0::{
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    ComplianceInstance, ComplianceInstanceWords, Digest,
};
use arm_core::utils::words_to_bytes;
use risc0_zkvm::serde::to_vec;

#[test]
fn compliance_journal_matches_risc0_serde() {
    let instance = ComplianceInstance {
        consumed_nullifier: Digest::from_bytes([0x11; 32]),
        consumed_logic_ref: Digest::from_bytes([0x22; 32]),
        consumed_commitment_tree_root: Digest::from_bytes([0x33; 32]),
        created_commitment: Digest::from_bytes([0x44; 32]),
        created_logic_ref: Digest::from_bytes([0x55; 32]),
        delta_x: [
            0xAAAA_0001,
            0xAAAA_0002,
            0xAAAA_0003,
            0xAAAA_0004,
            0xAAAA_0005,
            0xAAAA_0006,
            0xAAAA_0007,
            0xAAAA_0008,
        ],
        delta_y: [
            0xBBBB_0001,
            0xBBBB_0002,
            0xBBBB_0003,
            0xBBBB_0004,
            0xBBBB_0005,
            0xBBBB_0006,
            0xBBBB_0007,
            0xBBBB_0008,
        ],
    };

    assert_eq!(
        instance.to_journal().unwrap(),
        words_to_bytes(&to_vec(&instance).unwrap()).to_vec(),
    );
}

#[test]
fn logic_journal_matches_risc0_serde() {
    // Exercise all four payload categories with distinct shapes so an
    // encoding bug in any one category surfaces here.
    let instance = LogicInstance {
        tag: Digest::from_bytes([0x11; 32]),
        is_consumed: true,
        root: Digest::from_bytes([0x22; 32]),
        app_data: AppData {
            resource_payload: vec![ExpirableBlob {
                blob: vec![0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678],
                deletion_criterion: 1,
            }],
            discovery_payload: vec![ExpirableBlob {
                blob: vec![0xA, 0xB, 0xC, 0xD],
                deletion_criterion: 2,
            }],
            external_payload: vec![ExpirableBlob {
                blob: vec![0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888],
                deletion_criterion: 3,
            }],
            application_payload: vec![ExpirableBlob {
                blob: vec![1, 2, 3, 4, 5, 6, 7, 8],
                deletion_criterion: 4,
            }],
        },
    };

    assert_eq!(
        instance.to_journal().unwrap(),
        words_to_bytes(&to_vec(&instance).unwrap()).to_vec(),
    );
}

/// The batch aggregation guest commits
/// `(Vec<ComplianceInstanceWords>, Digest, Vec<Vec<u32>>, Vec<Digest>)` via
/// `env::commit`, which uses risc0_zkvm::serde. The Solana PA reconstructs
/// the same tuple and serializes it with borsh::to_vec to produce the
/// expected journal bytes. The two encoders happen to agree byte-for-byte
/// for this shape because it contains only fixed-size arrays, Vecs of
/// fixed-size items, and no bools/enums/Options. This test pins that
/// agreement — if either encoder ever diverges, this test fails and the
/// aggregation journal digest reconstruction in the PA must be updated.
#[test]
fn aggregation_tuple_borsh_matches_risc0_serde() {
    let compliance_instances: Vec<ComplianceInstanceWords> = vec![
        ComplianceInstanceWords {
            u32_words: [1u32; 56],
        },
        ComplianceInstanceWords {
            u32_words: [0xDEAD_BEEFu32; 56],
        },
    ];
    let compliance_key = Digest::from_bytes([0xAA; 32]);
    let logic_instances: Vec<Vec<u32>> = vec![
        vec![0x1111_1111, 0x2222_2222, 0x3333_3333],
        vec![0x4444_4444, 0x5555_5555],
        vec![0xDEAD_BEEF; 10],
    ];
    let logic_keys: Vec<Digest> = vec![
        Digest::from_bytes([0xBB; 32]),
        Digest::from_bytes([0xCC; 32]),
    ];

    let tuple = (
        compliance_instances,
        compliance_key,
        logic_instances,
        logic_keys,
    );

    let risc0_bytes = words_to_bytes(&to_vec(&tuple).unwrap()).to_vec();
    let borsh_bytes = borsh::to_vec(&tuple).unwrap();

    assert_eq!(risc0_bytes, borsh_bytes);
}

/// Empty-Vec variant of the aggregation tuple test. Locks the length-prefix
/// encoding (u32 little-endian) for each of the three Vec fields. If either
/// encoder changes how it writes a zero-length Vec, this test catches it.
#[test]
fn aggregation_tuple_empty_vecs_borsh_matches_risc0_serde() {
    let tuple: (
        Vec<ComplianceInstanceWords>,
        Digest,
        Vec<Vec<u32>>,
        Vec<Digest>,
    ) = (vec![], Digest::default(), vec![], vec![]);

    let risc0_bytes = words_to_bytes(&to_vec(&tuple).unwrap()).to_vec();
    let borsh_bytes = borsh::to_vec(&tuple).unwrap();

    assert_eq!(risc0_bytes, borsh_bytes);
}
