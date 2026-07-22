//! Delta proof verification for Solana on-chain programs.
//!
//! Uses Solana syscalls (hashv, secp256k1_recover) and solana-secp256k1 for
//! EC point arithmetic instead of k256, which exceeds SBF stack frame limits.
//! Requires solana-secp256k1 >= 0.2.1 for correct modular subtraction in ecadd.

use arm_core::compliance::ComplianceInstance;
use arm_core::transaction::{Delta, Transaction};

use crate::error::SolanaArmError;
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
/// canonical signature, matching the EVM adapter's ECDSA recovery semantics.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Collect tags (nullifiers and commitments) in compliance unit order.
/// Returns tags as 32-byte arrays in the order: [nf0, cm0, nf1, cm1, ...].
///
/// This produces the same byte sequence as `Transaction::get_delta_msg()` from `arm_core`,
/// but as separate 32-byte chunks suitable for Solana's `hashv` syscall.
/// `hashv` concatenates its inputs before hashing, so `hashv(collect_tags(tx))` ==
/// `Keccak-256(tx.get_delta_msg())`.
pub fn collect_tags(tx: &Transaction) -> Result<Vec<[u8; 32]>, SolanaArmError> {
    let mut tags = Vec::new();
    for action in &tx.actions {
        for cu in &action.compliance_units {
            let instance = ComplianceInstance::from_journal(&cu.instance)
                .map_err(|_| SolanaArmError::ComplianceInstanceParseFailed)?;
            tags.push(instance.consumed_nullifier.to_bytes());
            tags.push(instance.created_commitment.to_bytes());
        }
    }
    Ok(tags)
}

/// Compute the delta message hash = Keccak-256(concatenated tags) using Solana syscall.
pub fn compute_delta_msg_hash(tags: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = tags.iter().map(|t| t.as_slice()).collect();
    hashv(&refs).to_bytes()
}

/// Convert `[u32; 8]` word array to `[u8; 32]` using native-endian byte order.
///
/// Delta coordinates are secp256k1 field elements stored as `[u32; 8]` in the
/// `ComplianceInstance`. These words were originally created from big-endian
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

/// Parse delta coordinates from a compliance instance and return as an UncompressedPoint.
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

/// Accumulate delta points from all compliance instances using EC point addition.
/// Returns the accumulated point, or None if the result is the identity.
pub fn accumulate_deltas(tx: &Transaction) -> Result<Option<UncompressedPoint>, SolanaArmError> {
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &tx.actions {
        for cu in &action.compliance_units {
            let instance = ComplianceInstance::from_journal(&cu.instance)
                .map_err(|_| SolanaArmError::ComplianceInstanceParseFailed)?;
            let point = parse_delta_point(&instance.delta_x, &instance.delta_y);

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
    }

    Ok(accumulated)
}

/// Verify the delta proof using Solana syscalls.
pub fn verify_delta_proof(tx: &Transaction) -> Result<(), SolanaArmError> {
    // 1. Check delta_proof type
    let signature_bytes = match &tx.delta_proof {
        Delta::Proof(proof) => &proof.0,
        Delta::Witness(_) => return Err(SolanaArmError::ExpectedDeltaProof),
    };

    // 2. Collect tags
    let tags = collect_tags(tx)?;
    if tags.is_empty() {
        return Ok(());
    }

    // 3. Compute the delta message hash
    let msg_hash = compute_delta_msg_hash(&tags);

    // 4. Accumulate delta points
    let accumulated = accumulate_deltas(tx)?;

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

    // DeltaProof::to_bytes() stores recid as recid + 27 (Ethereum convention).
    let recid = signature_bytes[64]
        .checked_sub(27)
        .ok_or(SolanaArmError::InvalidDeltaProof)?;
    if recid > 1 {
        return Err(SolanaArmError::InvalidDeltaProof);
    }

    // 6. Recover public key
    let recovered_pubkey = secp256k1_recover(&msg_hash, recid, &sig_bytes)
        .map_err(|_| SolanaArmError::DeltaProofVerificationFailed)?;

    // 7. Compare full 64-byte uncompressed public keys directly.
    // The EVM PA uses Ethereum-style 20-byte address derivation (hash + truncate),
    // which reduces collision resistance from 256-bit to 160-bit unnecessarily.
    // On Solana, secp256k1_recover returns the full key — compare it directly.
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
    use arm_core::action::Action;
    use arm_core::compliance::ComplianceInstance;
    use arm_core::compliance_unit::ComplianceUnit;
    use arm_core::delta_types::DeltaProof;
    use arm_core::Digest;
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

    /// Build a Transaction with a single compliance unit whose delta point
    /// matches signing_key's public key, signed by that key.
    fn make_signed_transaction(signing_key: &SigningKey) -> Transaction {
        let vk = k256::ecdsa::VerifyingKey::from(signing_key);
        let encoded = vk.to_encoded_point(false);
        let x_bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y_bytes: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        let delta_x: [u32; 8] = words_from_bytes(x_bytes);
        let delta_y: [u32; 8] = words_from_bytes(y_bytes);

        let instance = ComplianceInstance {
            consumed_nullifier: Digest::default(),
            consumed_logic_ref: Digest::default(),
            consumed_commitment_tree_root: Digest::default(),
            created_commitment: Digest::default(),
            created_logic_ref: Digest::default(),
            delta_x,
            delta_y,
        };

        let cu = ComplianceUnit {
            proof: None,
            instance: instance.to_journal().unwrap(),
        };

        let action = Action {
            compliance_units: vec![cu],
            logic_verifier_inputs: vec![],
        };

        // Compute message hash (same path as verify_delta_proof)
        let nf_bytes = Digest::default().to_bytes();
        let cm_bytes = Digest::default().to_bytes();
        let msg_hash = compute_delta_msg_hash(&[nf_bytes, cm_bytes]);

        // Sign with k256
        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();

        let mut proof_bytes = [0u8; 65];
        proof_bytes[..64].copy_from_slice(&sig.to_bytes());
        proof_bytes[64] = recid.to_byte() + 27;

        Transaction {
            actions: vec![action],
            delta_proof: Delta::Proof(DeltaProof(proof_bytes)),
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    #[test]
    fn test_delta_proof() {
        let signing_key = SigningKey::random(&mut OsRng);
        let tx = make_signed_transaction(&signing_key);
        verify_delta_proof(&tx).unwrap();
    }

    #[test]
    fn delta_hash_matches_protocol_keccak_golden() {
        let tags: [[u8; 32]; 4] = std::array::from_fn(|index| {
            let index = (index as u64).to_le_bytes();
            solana_program::hash::hashv(&[b"golden-delta", &index]).to_bytes()
        });
        let expected = [
            0xf4, 0x3d, 0x99, 0xe0, 0x17, 0x75, 0x19, 0x96, 0x15, 0x91, 0x11, 0x4d, 0x45, 0x39,
            0xfd, 0xe6, 0x04, 0xed, 0xea, 0x5d, 0xce, 0xfc, 0xbd, 0xad, 0xf2, 0x77, 0x92, 0x0a,
            0xde, 0xaf, 0x8b, 0x39,
        ];

        assert_eq!(compute_delta_msg_hash(&tags), expected);
    }

    #[test]
    fn test_delta_proof_rejects_high_s_malleation() {
        use k256::elliptic_curve::PrimeField;

        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        let Delta::Proof(DeltaProof(proof)) = &mut tx.delta_proof else {
            unreachable!()
        };

        let s_bytes: [u8; 32] = proof[32..64].try_into().unwrap();
        let s = k256::Scalar::from_repr(s_bytes.into()).unwrap();
        proof[32..64].copy_from_slice(&(-s).to_bytes());
        proof[64] = ((proof[64] - 27) ^ 1) + 27;

        assert!(matches!(
            verify_delta_proof(&tx),
            Err(SolanaArmError::InvalidDeltaProof)
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

    /// Build a Transaction with a single compliance unit having the given delta point.
    fn make_tx_with_delta(delta_x: [u32; 8], delta_y: [u32; 8]) -> Transaction {
        let instance = ComplianceInstance {
            consumed_nullifier: Digest::default(),
            consumed_logic_ref: Digest::default(),
            consumed_commitment_tree_root: Digest::default(),
            created_commitment: Digest::default(),
            created_logic_ref: Digest::default(),
            delta_x,
            delta_y,
        };
        let cu = ComplianceUnit {
            proof: None,
            instance: instance.to_journal().unwrap(),
        };
        let action = Action {
            compliance_units: vec![cu],
            logic_verifier_inputs: vec![],
        };
        Transaction {
            actions: vec![action],
            delta_proof: Delta::Witness(arm_core::delta_types::DeltaWitness([0u8; 32])),
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    /// Build a Transaction with two compliance units having distinct tags and given delta points.
    fn make_tx_with_two_deltas(
        d1x: [u32; 8],
        d1y: [u32; 8],
        d2x: [u32; 8],
        d2y: [u32; 8],
    ) -> Transaction {
        let i1 = ComplianceInstance {
            consumed_nullifier: Digest::from_bytes([1u8; 32]),
            consumed_logic_ref: Digest::default(),
            consumed_commitment_tree_root: Digest::default(),
            created_commitment: Digest::from_bytes([2u8; 32]),
            created_logic_ref: Digest::default(),
            delta_x: d1x,
            delta_y: d1y,
        };
        let i2 = ComplianceInstance {
            consumed_nullifier: Digest::from_bytes([3u8; 32]),
            consumed_logic_ref: Digest::default(),
            consumed_commitment_tree_root: Digest::default(),
            created_commitment: Digest::from_bytes([4u8; 32]),
            created_logic_ref: Digest::default(),
            delta_x: d2x,
            delta_y: d2y,
        };
        let action = Action {
            compliance_units: vec![
                ComplianceUnit {
                    proof: None,
                    instance: i1.to_journal().unwrap(),
                },
                ComplianceUnit {
                    proof: None,
                    instance: i2.to_journal().unwrap(),
                },
            ],
            logic_verifier_inputs: vec![],
        };
        Transaction {
            actions: vec![action],
            delta_proof: Delta::Witness(arm_core::delta_types::DeltaWitness([0u8; 32])),
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    // =========================================================================
    // Curve point validation (parse_delta_point)
    // =========================================================================

    #[test]
    fn test_valid_generator_point() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_delta(gx, gy);
        let result = accumulate_deltas(&tx);
        assert!(
            result.is_ok(),
            "Generator point G must be accepted: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_some(), "G is not identity");
    }

    #[test]
    fn test_negated_y_is_valid() {
        let (neg_gx, neg_gy) = neg_generator_words();
        let tx = make_tx_with_delta(neg_gx, neg_gy);
        let result = accumulate_deltas(&tx);
        assert!(result.is_ok(), "-G must be accepted: {:?}", result.err());
        assert!(result.unwrap().is_some(), "-G is not identity");
    }

    // =========================================================================
    // Point arithmetic (accumulate_deltas)
    // =========================================================================

    #[test]
    fn test_point_doubling() {
        let (gx, gy) = generator_words();
        let g_point = accumulate_deltas(&make_tx_with_delta(gx, gy))
            .unwrap()
            .unwrap();
        let two_g_point = accumulate_deltas(&make_tx_with_two_deltas(gx, gy, gx, gy))
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
        let result = accumulate_deltas(&make_tx_with_two_deltas(gx, gy, neg_gx, neg_gy));
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

        // Compute 3G = G + 2G using k256 (reference)
        let g = k256::ProjectivePoint::GENERATOR;
        let three_g = (g + g + g).to_affine();
        let encoded = three_g.to_encoded_point(false);
        let expected_x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let expected_y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        // Compute G + 2G using solana-secp256k1's + operator
        let (gx, gy) = generator_words();
        let g_point = parse_delta_point(&gx, &gy);
        let two_g_result = Secp256k1::ecmul(&g_point, &SCALAR_TWO).unwrap();
        let three_g_result = g_point + two_g_result;

        assert_eq!(
            three_g_result.x(),
            expected_x,
            "ecadd x-coordinate must match k256"
        );
        assert_eq!(
            three_g_result.y(),
            expected_y,
            "ecadd y-coordinate must match k256"
        );
    }

    /// Verify the + operator is commutative: A + B == B + A.
    #[test]
    fn test_ecadd_commutative() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let g = k256::ProjectivePoint::GENERATOR;
        let two_g = (g + g).to_affine();
        let encoded = two_g.to_encoded_point(false);
        let x2: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y2: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        let (gx, gy) = generator_words();
        let g_point = parse_delta_point(&gx, &gy);
        let two_g_words = (words_from_bytes(x2), words_from_bytes(y2));
        let two_g_point = parse_delta_point(&two_g_words.0, &two_g_words.1);

        let ab = g_point + two_g_point;
        let ba = two_g_point + g_point;

        assert_eq!(ab.0, ba.0, "ecadd must be commutative");
    }

    // =========================================================================
    // Tag collection and message hash
    // =========================================================================

    #[test]
    fn test_collect_tags_order() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_two_deltas(gx, gy, gx, gy);
        let tags = collect_tags(&tx).unwrap();
        assert_eq!(tags.len(), 4, "2 CUs should produce 4 tags");
        assert_eq!(tags[0], [1u8; 32], "first tag = CU0 nullifier");
        assert_eq!(tags[1], [2u8; 32], "second tag = CU0 commitment");
        assert_eq!(tags[2], [3u8; 32], "third tag = CU1 nullifier");
        assert_eq!(tags[3], [4u8; 32], "fourth tag = CU1 commitment");
    }

    #[test]
    fn test_msg_hash_deterministic() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_delta(gx, gy);
        let tags = collect_tags(&tx).unwrap();
        let h1 = compute_delta_msg_hash(&tags);
        let h2 = compute_delta_msg_hash(&tags);
        assert_eq!(h1, h2, "Same tags must produce identical message hash");
    }

    // =========================================================================
    // Split transaction: real + padding compliance units
    // =========================================================================

    /// Regression test: EC point addition where the second point's x-coordinate
    /// is numerically smaller than the first. This triggered a panic in
    /// solana_secp256k1 < 0.2.1 due to raw UBig subtraction without adding p.
    #[test]
    fn test_ecadd_does_not_panic_on_smaller_x() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Get two distinct points where point_b.x < point_a.x
        let g = k256::ProjectivePoint::GENERATOR;
        let two_g = (g + g).to_affine();

        let g_encoded = k256::AffinePoint::GENERATOR.to_encoded_point(false);
        let two_g_encoded = two_g.to_encoded_point(false);

        let g_x: [u8; 32] = g_encoded.x().unwrap().as_slice().try_into().unwrap();
        let two_g_x: [u8; 32] = two_g_encoded.x().unwrap().as_slice().try_into().unwrap();

        // Determine which has the smaller x, then add with smaller-x second.
        // Big-endian [u8; 32] comparison is equivalent to numerical comparison.
        let (first, second) = if g_x > two_g_x {
            let first_y: [u8; 32] = g_encoded.y().unwrap().as_slice().try_into().unwrap();
            let second_y: [u8; 32] = two_g_encoded.y().unwrap().as_slice().try_into().unwrap();
            (
                parse_delta_point(&words_from_bytes(g_x), &words_from_bytes(first_y)),
                parse_delta_point(&words_from_bytes(two_g_x), &words_from_bytes(second_y)),
            )
        } else {
            let first_y: [u8; 32] = two_g_encoded.y().unwrap().as_slice().try_into().unwrap();
            let second_y: [u8; 32] = g_encoded.y().unwrap().as_slice().try_into().unwrap();
            (
                parse_delta_point(&words_from_bytes(two_g_x), &words_from_bytes(first_y)),
                parse_delta_point(&words_from_bytes(g_x), &words_from_bytes(second_y)),
            )
        };

        // This must NOT panic (solana_secp256k1 < 0.2.1 would panic here)
        let _ = first + second;
    }

    /// Regression test using delta coordinates from a real split withdrawal
    /// that panicked on-chain with `UBig result must not be negative`.
    ///
    /// The panic was in `solana_secp256k1`'s `Add<UncompressedPoint>` impl
    /// which computes `x_q - x_p` as a raw UBig subtraction (panics when
    /// x_q < x_p). Our `ecadd` fixes this by adding `p` before subtracting.
    ///
    /// Coordinates from: partial unwrap of 150 out of 300 USDC (split transaction).
    #[test]
    fn test_split_with_real_padding_delta_coordinates() {
        // CU 0: real compliance unit from the failed split
        let d1x: [u32; 8] = [
            436281146, 2920857657, 596527312, 1444609427, 135507158, 1733461838, 26316675,
            1082278278,
        ];
        let d1y: [u32; 8] = [
            1550517338, 2131773781, 3863212947, 2665082215, 2679122589, 2370594181, 1718588337,
            2702897137,
        ];
        // CU 1: padding compliance unit from the failed split
        let d2x: [u32; 8] = [
            1642325764, 796648147, 395144694, 3917860638, 4019340282, 497672579, 1148006934,
            4261521533,
        ];
        let d2y: [u32; 8] = [
            1856576270, 3021585445, 3338494523, 3407490559, 2736170793, 2022041402, 1488353443,
            4089188344,
        ];

        let tx = make_tx_with_two_deltas(d1x, d1y, d2x, d2y);
        // This must not panic. With the old code (solana_secp256k1's `+` operator),
        // this panicked with "UBig result must not be negative" because the second
        // point's x-coordinate was numerically smaller than the first.
        let result = accumulate_deltas(&tx);
        assert!(
            result.is_ok(),
            "Split with real padding coordinates must not panic or error: {:?}",
            result.err()
        );
    }

    /// Test accumulate_deltas with G + (-G) = identity (two CUs that cancel out).
    /// This is a valid split scenario where the padding unit's delta cancels
    /// the real unit's delta, producing the identity point.
    #[test]
    fn test_split_inverse_deltas_produce_identity() {
        let (gx, gy) = generator_words();
        let (neg_gx, neg_gy) = neg_generator_words();
        let tx = make_tx_with_two_deltas(gx, gy, neg_gx, neg_gy);
        let result = accumulate_deltas(&tx);
        assert!(
            result.is_ok(),
            "G + (-G) must not error: {:?}",
            result.err()
        );
        assert!(
            result.unwrap().is_none(),
            "G + (-G) should produce identity (None)"
        );
    }
}
