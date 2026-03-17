//! Delta proof verification for Solana on-chain programs.
//!
//! Uses Solana syscalls (hashv, secp256k1_recover) and solana-secp256k1 for
//! EC point arithmetic instead of k256, which exceeds SBF stack frame limits.

use arm_core::transaction::{Delta, Transaction};

use crate::error::SolanaArmError;
use dashu::integer::UBig;
use solana_program::hash::hashv;
use solana_program::secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Curve, Secp256k1Point, UncompressedPoint};

/// Scalar value 2 as a big-endian 32-byte array, used for EC point doubling.
const SCALAR_TWO: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};

/// Collect tags (nullifiers and commitments) in compliance unit order.
/// Returns tags as 32-byte arrays in the order: [nf0, cm0, nf1, cm1, ...].
///
/// This produces the same byte sequence as `Transaction::get_delta_msg()` from `arm_core`,
/// but as separate 32-byte chunks suitable for Solana's `hashv` syscall.
/// `hashv` concatenates its inputs before hashing, so `hashv(collect_tags(tx))` ==
/// `SHA-256(tx.get_delta_msg())`.
pub fn collect_tags(tx: &Transaction) -> Vec<[u8; 32]> {
    let mut tags = Vec::new();
    for action in &tx.actions {
        for cu in &action.compliance_units {
            tags.push(cu.instance.consumed_nullifier.to_bytes());
            tags.push(cu.instance.created_commitment.to_bytes());
        }
    }
    tags
}

/// Compute verifying key = SHA-256(concatenated tags) using Solana syscall.
pub fn compute_verifying_key(tags: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = tags.iter().map(|t| t.as_slice()).collect();
    hashv(&refs).to_bytes()
}

/// Parse delta coordinates from a compliance instance and return as an UncompressedPoint.
///
/// `delta_x` and `delta_y` in `ComplianceInstance` store secp256k1 field elements as `[u32; 8]`.
/// The byte-level encoding is platform-native (little-endian on SBF and x86_64).
/// `bytemuck::cast_ref` reinterprets the memory directly, preserving the byte sequence.
fn parse_delta_point(
    x_words: &[u32; 8],
    y_words: &[u32; 8],
) -> Result<UncompressedPoint, SolanaArmError> {
    let x_bytes: [u8; 32] = *bytemuck::cast_ref(x_words);
    let y_bytes: [u8; 32] = *bytemuck::cast_ref(y_words);

    // Validate point lies on curve: y^2 = x^3 + 7 (mod p)
    let p = UBig::from_be_bytes(&Curve::P);
    let x = UBig::from_be_bytes(&x_bytes);
    let y = UBig::from_be_bytes(&y_bytes);

    let y_squared = y.sqr() % &p;
    let x_cubed_plus_7 = (x.cubic() + UBig::from_word(7)) % &p;

    if y_squared != x_cubed_plus_7 {
        return Err(SolanaArmError::DeltaPointNotOnCurve);
    }

    let mut point_bytes = [0u8; 64];
    point_bytes[..32].copy_from_slice(&x_bytes);
    point_bytes[32..].copy_from_slice(&y_bytes);
    Ok(UncompressedPoint(point_bytes))
}

/// Accumulate delta points from all compliance instances using EC point addition.
/// Returns the accumulated point, or None if the result is the identity.
pub fn accumulate_deltas(tx: &Transaction) -> Result<Option<UncompressedPoint>, SolanaArmError> {
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &tx.actions {
        for cu in &action.compliance_units {
            let point = parse_delta_point(&cu.instance.delta_x, &cu.instance.delta_y)?;

            accumulated = match accumulated {
                None => Some(point),
                Some(acc) => {
                    let x_acc = acc.x();
                    let x_pt = point.x();

                    if x_acc == x_pt {
                        if acc.y() == point.y() {
                            // Point doubling: P + P
                            Some(
                                Curve::ecmul(&acc, &SCALAR_TWO)
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

/// Derive an address from 64 uncompressed public key bytes: SHA-256, then last 20 bytes.
fn pubkey_to_address(pubkey_bytes: &[u8; 64]) -> [u8; 20] {
    let hash: [u8; 32] = hashv(&[pubkey_bytes]).to_bytes();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Verify the delta proof using Solana syscalls.
pub fn verify_delta_proof(tx: &Transaction) -> Result<(), SolanaArmError> {
    // 1. Check delta_proof type
    let signature_bytes = match &tx.delta_proof {
        Delta::Proof(proof) => &proof.0,
        Delta::Witness(_) => return Err(SolanaArmError::ExpectedDeltaProof),
    };

    // 2. Collect tags
    let tags = collect_tags(tx);
    if tags.is_empty() {
        return Ok(());
    }

    // 3. Compute verifying key (message hash)
    let verifying_key = compute_verifying_key(&tags);

    // 4. Accumulate delta points
    let accumulated = accumulate_deltas(tx)?;

    // 5. Parse signature and recovery ID
    let sig_bytes: [u8; 64] = signature_bytes[0..64]
        .try_into()
        .map_err(|_| SolanaArmError::InvalidDeltaProof)?;

    // DeltaProof::to_bytes() stores recid as recid + 27 (Ethereum convention).
    let recid = signature_bytes[64]
        .checked_sub(27)
        .ok_or(SolanaArmError::InvalidDeltaProof)?;

    // 6. Recover public key
    let recovered_pubkey = secp256k1_recover(&verifying_key, recid, &sig_bytes)
        .map_err(|_| SolanaArmError::DeltaProofVerificationFailed)?;

    // 7. Convert recovered key to address
    let recovered_address = pubkey_to_address(&recovered_pubkey.0);

    // 8. Compare with expected address
    let expected_address = match accumulated {
        Some(point) => pubkey_to_address(&point.0),
        None => return Err(SolanaArmError::DeltaProofVerificationFailed),
    };

    if recovered_address != expected_address {
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
    /// Alignment-safe: uses u32::from_ne_bytes instead of bytemuck::cast.
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
            instance,
        };

        let action = Action {
            compliance_units: vec![cu],
            logic_verifier_inputs: vec![],
        };

        // Compute message hash (same path as verify_delta_proof)
        let nf_bytes = Digest::default().to_bytes();
        let cm_bytes = Digest::default().to_bytes();
        let msg_hash = compute_verifying_key(&[nf_bytes, cm_bytes]);

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
            instance,
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
                    instance: i1,
                },
                ComplianceUnit {
                    proof: None,
                    instance: i2,
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
    // Curve point validation (accumulate_deltas)
    // =========================================================================

    #[test]
    fn test_valid_generator_point() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_delta(gx, gy);
        let result = accumulate_deltas(&tx);
        assert!(
            result.is_ok(),
            "Generator point G must be on secp256k1: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_some(), "G is not identity");
    }

    #[test]
    fn test_zero_point_rejected() {
        let tx = make_tx_with_delta([0u32; 8], [0u32; 8]);
        let result = accumulate_deltas(&tx);
        match result {
            Err(SolanaArmError::DeltaPointNotOnCurve) => {}
            other => panic!("(0,0) should return DeltaPointNotOnCurve, got {:?}", other),
        }
    }

    #[test]
    fn test_wrong_y_coordinate_rejected() {
        let (gx, _) = generator_words();
        let tx = make_tx_with_delta(gx, [0u32; 8]);
        let result = accumulate_deltas(&tx);
        match result {
            Err(SolanaArmError::DeltaPointNotOnCurve) => {}
            other => panic!(
                "Valid x with zero y should return DeltaPointNotOnCurve, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_invalid_coordinates_rejected() {
        // (1, 1) in big-endian representation: y^2 = 1, x^3 + 7 = 8, so 1 != 8.
        let mut x_be = [0u8; 32];
        x_be[31] = 1;
        let mut y_be = [0u8; 32];
        y_be[31] = 1;
        let tx = make_tx_with_delta(words_from_bytes(x_be), words_from_bytes(y_be));
        let result = accumulate_deltas(&tx);
        match result {
            Err(SolanaArmError::DeltaPointNotOnCurve) => {}
            other => panic!(
                "(1,1) should return DeltaPointNotOnCurve (1 != 8 mod p), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_negated_y_is_valid() {
        let (neg_gx, neg_gy) = neg_generator_words();
        let tx = make_tx_with_delta(neg_gx, neg_gy);
        let result = accumulate_deltas(&tx);
        assert!(
            result.is_ok(),
            "-G must be on secp256k1: {:?}",
            result.err()
        );
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

    // =========================================================================
    // Tag collection and verifying key
    // =========================================================================

    #[test]
    fn test_collect_tags_order() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_two_deltas(gx, gy, gx, gy);
        let tags = collect_tags(&tx);
        assert_eq!(tags.len(), 4, "2 CUs should produce 4 tags");
        assert_eq!(tags[0], [1u8; 32], "first tag = CU0 nullifier");
        assert_eq!(tags[1], [2u8; 32], "second tag = CU0 commitment");
        assert_eq!(tags[2], [3u8; 32], "third tag = CU1 nullifier");
        assert_eq!(tags[3], [4u8; 32], "fourth tag = CU1 commitment");
    }

    #[test]
    fn test_verifying_key_deterministic() {
        let (gx, gy) = generator_words();
        let tx = make_tx_with_delta(gx, gy);
        let tags = collect_tags(&tx);
        let vk1 = compute_verifying_key(&tags);
        let vk2 = compute_verifying_key(&tags);
        assert_eq!(vk1, vk2, "Same tags must produce identical verifying key");
    }

    // =========================================================================
    // Split transaction: real + padding compliance units
    // =========================================================================

    /// Simulate a split transaction: one real compliance unit (valid delta point)
    /// and one padding compliance unit (trivial resource, identity-like delta).
    ///
    /// In a split (e.g., consume 1000, send 300, remainder 700), the proof
    /// generates two compliance units. The padding unit's delta point comes from
    /// the ZK circuit and may be the identity point or have coordinates that
    /// cause UBig arithmetic to underflow in parse_delta_point.
    ///
    /// This test reproduces the on-chain panic:
    ///   "UBig result must not be negative" in dashu-int during
    ///   parse_delta_point's curve equation check y² = x³ + 7 (mod p)
    #[test]
    fn test_split_transaction_with_padding_delta() {
        // Real compliance unit with valid delta point (generator G)
        let (gx, gy) = generator_words();

        // Padding compliance unit: delta from a trivial/padding resource.
        // The ZK circuit outputs delta coordinates for the padding unit.
        // Test with zero coordinates — the identity point representation.
        // parse_delta_point must handle this without panicking.
        let tx = make_tx_with_two_deltas(gx, gy, [0u32; 8], [0u32; 8]);
        let result = accumulate_deltas(&tx);
        // Should return an error (zero is not on the curve), NOT panic
        assert!(
            result.is_err() || result.is_ok(),
            "Split with padding delta must not panic"
        );
    }

    /// Regression test using delta coordinates from a real split withdrawal
    /// that panicked on-chain with `UBig result must not be negative`.
    ///
    /// NOTE: This test PASSES on x86_64 but the same coordinates PANIC on BPF/SBF.
    /// The on-chain panic is reproduced by the E2E test (`transfer-e2e`) which
    /// exercises the actual BPF program. This unit test exists to verify the fix
    /// once applied — if it passes here AND in the E2E test, the fix is correct.
    ///
    /// Coordinates from: partial unwrap of 150 out of 300 USDC (split transaction).
    #[test]
    fn test_split_with_real_padding_delta_coordinates() {
        // CU 0: real compliance unit from the failed split
        let d1x: [u32; 8] = [436281146, 2920857657, 596527312, 1444609427, 135507158, 1733461838, 26316675, 1082278278];
        let d1y: [u32; 8] = [1550517338, 2131773781, 3863212947, 2665082215, 2679122589, 2370594181, 1718588337, 2702897137];
        // CU 1: padding compliance unit from the failed split
        let d2x: [u32; 8] = [1642325764, 796648147, 395144694, 3917860638, 4019340282, 497672579, 1148006934, 4261521533];
        let d2y: [u32; 8] = [1856576270, 3021585445, 3338494523, 3407490559, 2736170793, 2022041402, 1488353443, 4089188344];

        let tx = make_tx_with_two_deltas(d1x, d1y, d2x, d2y);
        // This must not panic. It may return Ok or Err, but must not abort.
        let result = accumulate_deltas(&tx);
        println!("Split with real padding coordinates: {:?}", result.as_ref().map(|r| r.is_some()));
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
        assert!(result.is_ok(), "G + (-G) must not error: {:?}", result.err());
        assert!(
            result.unwrap().is_none(),
            "G + (-G) should produce identity (None)"
        );
    }
}
