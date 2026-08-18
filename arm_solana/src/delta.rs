//! Delta proof verification for Solana on-chain programs.
//!
//! The delta proof scheme is single and chain-agnostic — an ECDSA signature
//! over secp256k1 on the keccak-hashed concatenation of action tree roots —
//! but k256's curve arithmetic exceeds Solana's SBF stack-frame limits and
//! soft hashing/recovery would burn enormous compute. Verification therefore
//! goes through the runtime's native primitives: the `secp256k1_recover` and
//! keccak `hashv` syscalls, plus `solana-secp256k1` (>= 0.2.1 for its ecadd
//! modular-subtraction fix) for the one operation no syscall provides,
//! summing the per-action delta points. The k256 cross-check tests pin this
//! implementation against the host-side one.
//!
//! On-chain transactions are always aggregated, so the delta inputs — the
//! per-action delta points and the action tree roots forming the delta
//! message — are read from the proof-backed
//! [`AggregationInstance`](anoma_rm_risc0::aggregation_instance::AggregationInstance),
//! never from `actions`.

use anoma_rm_risc0::aggregation_instance::AggregationInstance;
use anoma_rm_risc0::transaction::{Delta, Transaction};

use crate::error::SolanaArmError;
use crate::journal::require_aggregation;
use solana_program::keccak::hashv;
use solana_program::secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Secp256k1, Secp256k1Point, UncompressedPoint};

/// Scalar value 2 as a big-endian 32-byte array, used for EC point doubling.
const SCALAR_TWO: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};

/// Half the secp256k1 scalar order, encoded big-endian.
///
/// Requiring `s` at or below this boundary gives every ECDSA authorization one
/// canonical signature, matching `DeltaProof::verify`'s low-s check upstream.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Collect the action tree roots in action order, as 32-byte arrays.
///
/// This produces the same byte sequence as `AggregationInstance::delta_msg()`,
/// but as separate 32-byte chunks suitable for Solana's `hashv` syscall.
/// `hashv` concatenates its inputs before hashing, so
/// `hashv(collect_roots(instance))` == `Keccak-256(instance.delta_msg())`.
pub fn collect_roots(instance: &AggregationInstance) -> Vec<[u8; 32]> {
    instance
        .actions
        .iter()
        .map(|action| {
            action
                .action_tree_root
                .as_bytes()
                .try_into()
                .expect("a digest is always 32 bytes")
        })
        .collect()
}

/// Compute the delta message hash = Keccak-256(concatenated roots) using Solana syscall.
pub fn compute_delta_msg_hash(roots: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = roots.iter().map(|t| t.as_slice()).collect();
    hashv(&refs).to_bytes()
}

/// Convert `[u32; 8]` word array to `[u8; 32]` using native-endian byte order.
///
/// Delta coordinates are secp256k1 field elements stored as `[u32; 8]` in the
/// `AggregationInstance`. These words were originally created from big-endian
/// `[u8; 32]` bytes via bytemuck/transmute on a little-endian platform (the
/// RISC-V zkVM). On a same-endianness target (SBF is also LE), reinterpreting
/// via native byte order recovers the original big-endian byte array.
fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    bytes
}

/// Parse delta coordinates from an aggregated action and return as an UncompressedPoint.
///
/// The curve equation check (y² = x³ + 7 mod p) is intentionally omitted here.
/// The delta coordinates come from a verified Groth16 proof — the compliance circuit
/// guarantees they are valid secp256k1 points.
fn parse_delta_point(x_words: &[u32; 8], y_words: &[u32; 8]) -> UncompressedPoint {
    let x_bytes = words_to_bytes(x_words);
    let y_bytes = words_to_bytes(y_words);

    let mut point_bytes = [0u8; 64];
    point_bytes[..32].copy_from_slice(&x_bytes);
    point_bytes[32..].copy_from_slice(&y_bytes);
    UncompressedPoint(point_bytes)
}

/// Accumulate delta points from all aggregated actions using EC point addition.
/// Returns the accumulated point, or None if the result is the identity.
pub fn accumulate_deltas(
    instance: &AggregationInstance,
) -> Result<Option<UncompressedPoint>, SolanaArmError> {
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &instance.actions {
        let point = parse_delta_point(&action.delta_x, &action.delta_y);

        accumulated = match accumulated {
            None => Some(point),
            Some(acc) => {
                let x_acc = acc.x();
                let x_pt = point.x();

                if x_acc == x_pt {
                    if acc.y() == point.y() {
                        // Point doubling: P + P
                        Some(
                            Secp256k1::ecmul(&acc, &SCALAR_TWO)
                                .map_err(|_| SolanaArmError::DeltaPointNotOnCurve)?,
                        )
                    } else {
                        // Inverse points: P + (-P) = identity
                        None
                    }
                } else {
                    Some(acc + point)
                }
            }
        };
    }

    Ok(accumulated)
}

/// Verify the delta proof using Solana syscalls.
pub fn verify_delta_proof(tx: &Transaction) -> Result<(), SolanaArmError> {
    // 1. Check delta_proof type. `DeltaProof::to_bytes` emits the 65-byte
    //    wire form with the Ethereum-style {27, 28} recovery byte.
    let signature_bytes = match &tx.delta_proof {
        Delta::Proof(proof) => proof.to_bytes(),
        Delta::Witness(_) => return Err(SolanaArmError::ExpectedDeltaProof),
    };

    // 2. The aggregation instance is the only trusted source of delta inputs.
    let instance = require_aggregation(tx)?;

    // 3. Compute the delta message hash from the action tree roots.
    let roots = collect_roots(instance);
    let msg_hash = compute_delta_msg_hash(&roots);

    // 4. Accumulate delta points
    let accumulated = accumulate_deltas(instance)?;

    // 5. Parse signature and recovery ID
    let sig_bytes: [u8; 64] = signature_bytes[0..64]
        .try_into()
        .map_err(|_| SolanaArmError::InvalidDeltaProof)?;

    let s_bytes: [u8; 32] = sig_bytes[32..]
        .try_into()
        .map_err(|_| SolanaArmError::InvalidDeltaProof)?;
    if s_bytes > SECP256K1_HALF_ORDER {
        return Err(SolanaArmError::InvalidDeltaProof);
    }

    let recid = signature_bytes[64]
        .checked_sub(27)
        .ok_or(SolanaArmError::InvalidDeltaProof)?;
    if recid > 1 {
        return Err(SolanaArmError::InvalidDeltaProof);
    }

    // 6. Recover public key
    let recovered_pubkey = secp256k1_recover(&msg_hash, recid, &sig_bytes)
        .map_err(|_| SolanaArmError::DeltaProofVerificationFailed)?;

    // 7. Compare full 64-byte uncompressed public keys directly. Recovery
    //    returns the full key, so nothing is gained by hashing/truncating it
    //    to an address first — direct comparison keeps the full 256-bit
    //    collision resistance. An empty action set or an identity
    //    accumulation has no valid public key and is rejected, matching
    //    `DeltaInstance::new` upstream failing on the identity point.
    let expected_pubkey = match accumulated {
        Some(point) => point.0,
        None => return Err(SolanaArmError::DeltaProofVerificationFailed),
    };

    if recovered_pubkey.0 != expected_pubkey {
        return Err(SolanaArmError::DeltaMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anoma_rm_risc0::aggregation_instance::{ActionAggregated, AggregationInstance};
    use anoma_rm_risc0::delta_proof::DeltaProof;
    use anoma_rm_risc0::delta_proof::DeltaWitness;
    use anoma_rm_risc0::transaction::Aggregation;
    use anoma_rm_risc0::Digest;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;

    /// Convert a 32-byte array to [u32; 8] using native-endian byte interpretation.
    /// Inverse of `words_to_bytes`: reinterprets each 4-byte chunk as a u32 in
    /// native byte order, matching how bytemuck/transmute would create the words.
    fn words_from_bytes(bytes: [u8; 32]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            words[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }
        words
    }

    /// Wrap aggregated actions into a transaction with the given delta.
    fn make_tx(actions: Vec<ActionAggregated>, delta_proof: Delta) -> Transaction {
        Transaction {
            actions: None,
            delta_proof,
            expected_balance: None,
            aggregation: Some(Aggregation {
                proof: vec![],
                instance: AggregationInstance {
                    compliance_key: Digest::default(),
                    kind_table_commitment: Digest::default(),
                    actions,
                },
            }),
        }
    }

    fn make_action(
        delta_x: [u32; 8],
        delta_y: [u32; 8],
        action_tree_root: Digest,
    ) -> ActionAggregated {
        ActionAggregated {
            consumed_publics: vec![],
            created_publics: vec![],
            delta_x,
            delta_y,
            action_tree_root,
        }
    }

    /// Build a Transaction with a single aggregated action whose delta point
    /// matches signing_key's public key, signed by that key over the same
    /// message hash `verify_delta_proof` computes.
    fn make_signed_transaction(signing_key: &SigningKey) -> Transaction {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let vk = k256::ecdsa::VerifyingKey::from(signing_key);
        let encoded = vk.to_encoded_point(false);
        let x_bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y_bytes: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        let root = Digest::default();
        let action = make_action(words_from_bytes(x_bytes), words_from_bytes(y_bytes), root);

        let msg_hash = compute_delta_msg_hash(&[root.as_bytes().try_into().unwrap()]);

        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();

        let mut proof_bytes = [0u8; 65];
        proof_bytes[..64].copy_from_slice(&sig.to_bytes());
        proof_bytes[64] = recid.to_byte() + 27;

        make_tx(
            vec![action],
            Delta::Proof(DeltaProof::from_bytes(&proof_bytes).unwrap()),
        )
    }

    #[test]
    fn test_delta_proof() {
        let signing_key = SigningKey::random(&mut OsRng);
        let tx = make_signed_transaction(&signing_key);
        verify_delta_proof(&tx).unwrap();
    }

    #[test]
    fn delta_hash_matches_protocol_keccak_golden() {
        let roots: [[u8; 32]; 4] = std::array::from_fn(|index| {
            let index = (index as u64).to_le_bytes();
            solana_program::hash::hashv(&[b"golden-delta", &index]).to_bytes()
        });
        let expected = [
            0xf4, 0x3d, 0x99, 0xe0, 0x17, 0x75, 0x19, 0x96, 0x15, 0x91, 0x11, 0x4d, 0x45, 0x39,
            0xfd, 0xe6, 0x04, 0xed, 0xea, 0x5d, 0xce, 0xfc, 0xbd, 0xad, 0xf2, 0x77, 0x92, 0x0a,
            0xde, 0xaf, 0x8b, 0x39,
        ];

        assert_eq!(compute_delta_msg_hash(&roots), expected);
    }

    #[test]
    fn test_delta_proof_rejects_high_s_malleation() {
        use k256::elliptic_curve::PrimeField;

        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        let Delta::Proof(proof) = &tx.delta_proof else {
            unreachable!()
        };

        // Negate s and flip the recovery bit — the classic malleation.
        let mut bytes = proof.to_bytes();
        let s_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
        let s = k256::Scalar::from_repr(s_bytes.into()).unwrap();
        bytes[32..64].copy_from_slice(&(-s).to_bytes());
        bytes[64] = ((bytes[64] - 27) ^ 1) + 27;
        tx.delta_proof = Delta::Proof(DeltaProof::from_bytes(&bytes).unwrap());

        assert!(matches!(
            verify_delta_proof(&tx),
            Err(SolanaArmError::InvalidDeltaProof)
        ));
    }

    #[test]
    fn test_unaggregated_transaction_rejected() {
        let tx = Transaction {
            actions: Some(vec![]),
            delta_proof: Delta::Witness(DeltaWitness::from_bytes(&[7u8; 32]).unwrap()),
            expected_balance: None,
            aggregation: None,
        };
        assert!(matches!(
            verify_delta_proof(&tx),
            Err(SolanaArmError::ExpectedDeltaProof)
        ));

        let signing_key = SigningKey::random(&mut OsRng);
        let mut aggregated = make_signed_transaction(&signing_key);
        aggregated.aggregation = None;
        assert!(matches!(
            verify_delta_proof(&aggregated),
            Err(SolanaArmError::MissingAggregation)
        ));
    }

    #[test]
    fn test_ambiguous_transaction_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        tx.actions = Some(vec![]);
        assert!(matches!(
            verify_delta_proof(&tx),
            Err(SolanaArmError::AmbiguousTransaction)
        ));
    }

    // =========================================================================
    // Helpers for curve point testing
    // =========================================================================

    /// Get the secp256k1 generator point G as `[u32; 8]` word arrays.
    fn generator_words() -> ([u32; 8], [u32; 8]) {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let g = k256::AffinePoint::GENERATOR;
        let encoded = g.to_encoded_point(false);
        let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();
        (words_from_bytes(x), words_from_bytes(y))
    }

    /// Get the negated generator point -G as `[u32; 8]` word arrays.
    fn neg_generator_words() -> ([u32; 8], [u32; 8]) {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let neg_g = (-k256::ProjectivePoint::GENERATOR).to_affine();
        let encoded = neg_g.to_encoded_point(false);
        let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();
        (words_from_bytes(x), words_from_bytes(y))
    }

    /// Build an AggregationInstance with a single action having the given delta point.
    fn make_instance_with_delta(delta_x: [u32; 8], delta_y: [u32; 8]) -> AggregationInstance {
        AggregationInstance {
            compliance_key: Digest::default(),
            kind_table_commitment: Digest::default(),
            actions: vec![make_action(delta_x, delta_y, Digest::default())],
        }
    }

    /// Build an AggregationInstance with two actions having distinct roots and
    /// the given delta points.
    fn make_instance_with_two_deltas(
        d1x: [u32; 8],
        d1y: [u32; 8],
        d2x: [u32; 8],
        d2y: [u32; 8],
    ) -> AggregationInstance {
        AggregationInstance {
            compliance_key: Digest::default(),
            kind_table_commitment: Digest::default(),
            actions: vec![
                make_action(d1x, d1y, Digest::from([1u8; 32])),
                make_action(d2x, d2y, Digest::from([2u8; 32])),
            ],
        }
    }

    #[test]
    fn test_valid_generator_point() {
        let (gx, gy) = generator_words();
        let result = accumulate_deltas(&make_instance_with_delta(gx, gy));
        assert!(result.is_ok(), "G must be accepted: {:?}", result.err());
        assert!(result.unwrap().is_some(), "G is not identity");
    }

    #[test]
    fn test_point_doubling() {
        let (gx, gy) = generator_words();
        let g_point = accumulate_deltas(&make_instance_with_delta(gx, gy))
            .unwrap()
            .unwrap();
        let two_g_point = accumulate_deltas(&make_instance_with_two_deltas(gx, gy, gx, gy))
            .unwrap()
            .unwrap();
        assert_ne!(
            g_point.0, two_g_point.0,
            "2G must have different coordinates than G"
        );
    }

    #[test]
    fn test_inverse_points_cancel() {
        let (gx, gy) = generator_words();
        let (neg_gx, neg_gy) = neg_generator_words();
        let result = accumulate_deltas(&make_instance_with_two_deltas(gx, gy, neg_gx, neg_gy));
        assert!(
            result.is_ok(),
            "G + (-G) should succeed: {:?}",
            result.err()
        );
        assert!(
            result.unwrap().is_none(),
            "G + (-G) should equal identity (None)"
        );
    }

    /// Verify the crate's + operator produces the same result as k256 for G + 2G.
    #[test]
    fn test_ecadd_matches_k256() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let g = k256::ProjectivePoint::GENERATOR;
        let three_g = (g + g + g).to_affine();
        let encoded = three_g.to_encoded_point(false);
        let expected_x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let expected_y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        let (gx, gy) = generator_words();
        let g_point = parse_delta_point(&gx, &gy);
        let two_g_result = Secp256k1::ecmul(&g_point, &SCALAR_TWO).unwrap();
        let three_g_result = g_point + two_g_result;

        assert_eq!(three_g_result.x(), expected_x, "ecadd x must match k256");
        assert_eq!(three_g_result.y(), expected_y, "ecadd y must match k256");
    }

    #[test]
    fn test_collect_roots_matches_delta_msg() {
        let (gx, gy) = generator_words();
        let instance = make_instance_with_two_deltas(gx, gy, gx, gy);
        let concatenated: Vec<u8> = collect_roots(&instance).concat();
        assert_eq!(concatenated, instance.delta_msg());
        assert_eq!(collect_roots(&instance)[0], [1u8; 32]);
        assert_eq!(collect_roots(&instance)[1], [2u8; 32]);
    }

    /// Regression test using delta coordinates from a real split withdrawal
    /// that panicked on-chain with `UBig result must not be negative` in
    /// solana_secp256k1 < 0.2.1 (raw UBig subtraction in ecadd when
    /// x_q < x_p; fixed by adding p before subtracting).
    ///
    /// Coordinates from: partial unwrap of 150 out of 300 USDC (split transaction).
    #[test]
    fn test_split_with_real_padding_delta_coordinates() {
        let d1x: [u32; 8] = [
            436281146, 2920857657, 596527312, 1444609427, 135507158, 1733461838, 26316675,
            1082278278,
        ];
        let d1y: [u32; 8] = [
            1550517338, 2131773781, 3863212947, 2665082215, 2679122589, 2370594181, 1718588337,
            2702897137,
        ];
        let d2x: [u32; 8] = [
            1642325764, 796648147, 395144694, 3917860638, 4019340282, 497672579, 1148006934,
            4261521533,
        ];
        let d2y: [u32; 8] = [
            1856576270, 3021585445, 3338494523, 3407490559, 2736170793, 2022041402, 1488353443,
            4089188344,
        ];

        let instance = make_instance_with_two_deltas(d1x, d1y, d2x, d2y);
        let result = accumulate_deltas(&instance);
        assert!(
            result.is_ok(),
            "Split with real padding coordinates must not panic or error: {:?}",
            result.err()
        );
    }
}
