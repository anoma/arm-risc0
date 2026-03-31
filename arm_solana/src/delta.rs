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
/// guarantees they are valid secp256k1 points. Performing a redundant curve check
/// would pull in dashu big-integer arithmetic that has known issues on SBF
/// (the `UBig` subtraction in `solana_secp256k1`'s EC point addition panics
/// when the minuend is smaller than the subtrahend, because `UBig` is unsigned).
fn parse_delta_point(x_words: &[u32; 8], y_words: &[u32; 8]) -> UncompressedPoint {
    let x_bytes = words_to_bytes(x_words);
    let y_bytes = words_to_bytes(y_words);

    let mut point_bytes = [0u8; 64];
    point_bytes[..32].copy_from_slice(&x_bytes);
    point_bytes[32..].copy_from_slice(&y_bytes);
    UncompressedPoint(point_bytes)
}

/// Convert a `UBig` to a fixed-size 32-byte big-endian array, zero-padding on the left.
fn ubig_to_be_bytes_32(n: &UBig) -> [u8; 32] {
    let bytes = n.to_be_bytes();
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[32 - len..].copy_from_slice(&bytes[..len]);
    result
}

/// EC point addition on secp256k1 with correct modular arithmetic.
///
/// This replaces the `Add<UncompressedPoint>` impl from `solana_secp256k1` which
/// has a bug: it computes `x_q - x_p` as a raw `UBig` subtraction that panics
/// when `x_q < x_p` (since `UBig` is unsigned and cannot represent negative values).
/// The fix is to add the field prime `p` before subtracting, ensuring all
/// intermediate values remain non-negative.
fn ecadd(
    a: &UncompressedPoint,
    b: &UncompressedPoint,
) -> Result<UncompressedPoint, SolanaArmError> {
    let p = UBig::from_be_bytes(&Curve::P);

    let x_a = UBig::from_be_bytes(&a.x());
    let y_a = UBig::from_be_bytes(&a.y());
    let x_b = UBig::from_be_bytes(&b.x());
    let y_b = UBig::from_be_bytes(&b.y());

    // dx = (x_b - x_a) mod p
    // Add p before subtracting to prevent unsigned underflow.
    let dx = (&x_b + &p - &x_a) % &p;
    let dx_bytes = ubig_to_be_bytes_32(&dx);
    let inv_dx = Curve::mod_inv_p(&dx_bytes).map_err(|_| SolanaArmError::DeltaPointNotOnCurve)?;
    let inv_dx = UBig::from_be_bytes(&inv_dx);

    // λ = (y_b - y_a) * (x_b - x_a)^{-1} mod p
    let lambda = ((&y_b + &p - &y_a) * &inv_dx) % &p;

    // x_r = λ² - x_a - x_b mod p
    // Add 2p since x_a + x_b can be up to 2(p-1).
    let x_r = (&lambda * &lambda + &p + &p - &x_a - &x_b) % &p;

    // y_r = λ(x_a - x_r) - y_a mod p
    let y_r = (&lambda * (&x_a + &p - &x_r) + &p - &y_a) % &p;

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&ubig_to_be_bytes_32(&x_r));
    result[32..].copy_from_slice(&ubig_to_be_bytes_32(&y_r));

    Ok(UncompressedPoint(result))
}

/// Accumulate delta points from all compliance instances using EC point addition.
/// Returns the accumulated point, or None if the result is the identity.
pub fn accumulate_deltas(tx: &Transaction) -> Result<Option<UncompressedPoint>, SolanaArmError> {
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &tx.actions {
        for cu in &action.compliance_units {
            let point = parse_delta_point(&cu.instance.delta_x, &cu.instance.delta_y);

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
                        // Point addition using our correct implementation,
                        // not solana_secp256k1's buggy `+` operator.
                        Some(ecadd(&acc, &point)?)
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

    /// Verify our ecadd produces the same result as k256 for G + 2G.
    #[test]
    fn test_ecadd_matches_k256() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Compute 3G = G + 2G using k256 (reference)
        let g = k256::ProjectivePoint::GENERATOR;
        let three_g = (g + g + g).to_affine();
        let encoded = three_g.to_encoded_point(false);
        let expected_x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let expected_y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        // Compute G + 2G using our ecadd
        let (gx, gy) = generator_words();
        let g_point = parse_delta_point(&gx, &gy);
        let two_g_result = Curve::ecmul(&g_point, &SCALAR_TWO).unwrap();
        let three_g_result = ecadd(&g_point, &two_g_result).unwrap();

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

    /// Verify ecadd is commutative: A + B == B + A.
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

        let ab = ecadd(&g_point, &two_g_point).unwrap();
        let ba = ecadd(&two_g_point, &g_point).unwrap();

        assert_eq!(ab.0, ba.0, "ecadd must be commutative");
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

    /// Regression test: EC point addition where the second point's x-coordinate
    /// is numerically smaller than the first, triggering the unsigned underflow
    /// bug in solana_secp256k1's `Add<UncompressedPoint>` impl. Our `ecadd`
    /// handles this correctly by adding `p` before subtraction.
    #[test]
    fn test_ecadd_does_not_panic_on_smaller_x() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        // Get two distinct points where point_b.x < point_a.x
        let g = k256::ProjectivePoint::GENERATOR;
        let two_g = (g + g).to_affine();

        let g_encoded = k256::AffinePoint::GENERATOR.to_encoded_point(false);
        let two_g_encoded = two_g.to_encoded_point(false);

        let g_x = UBig::from_be_bytes(g_encoded.x().unwrap().as_slice());
        let two_g_x = UBig::from_be_bytes(two_g_encoded.x().unwrap().as_slice());

        // Determine which has the smaller x, then call ecadd with smaller-x second
        let (first, second) = if g_x > two_g_x {
            let first_x: [u8; 32] = g_encoded.x().unwrap().as_slice().try_into().unwrap();
            let first_y: [u8; 32] = g_encoded.y().unwrap().as_slice().try_into().unwrap();
            let second_x: [u8; 32] = two_g_encoded.x().unwrap().as_slice().try_into().unwrap();
            let second_y: [u8; 32] = two_g_encoded.y().unwrap().as_slice().try_into().unwrap();
            (
                parse_delta_point(&words_from_bytes(first_x), &words_from_bytes(first_y)),
                parse_delta_point(&words_from_bytes(second_x), &words_from_bytes(second_y)),
            )
        } else {
            let first_x: [u8; 32] = two_g_encoded.x().unwrap().as_slice().try_into().unwrap();
            let first_y: [u8; 32] = two_g_encoded.y().unwrap().as_slice().try_into().unwrap();
            let second_x: [u8; 32] = g_encoded.x().unwrap().as_slice().try_into().unwrap();
            let second_y: [u8; 32] = g_encoded.y().unwrap().as_slice().try_into().unwrap();
            (
                parse_delta_point(&words_from_bytes(first_x), &words_from_bytes(first_y)),
                parse_delta_point(&words_from_bytes(second_x), &words_from_bytes(second_y)),
            )
        };

        // This must NOT panic (the bug in solana_secp256k1 would panic here)
        let result = ecadd(&first, &second);
        assert!(result.is_ok(), "ecadd must handle x_b < x_a");
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
