//! Delta proof verification for Solana on-chain programs.
//!
//! The delta proof scheme is single and chain-agnostic — an ECDSA signature
//! over the keccak hash of the concatenated action-tree roots, verified by
//! key recovery against the sum of the per-action delta points. This module
//! implements the verifier with the Solana runtime's native primitives —
//! the keccak (`hashv`) and `secp256k1_recover` syscalls, plus
//! `solana-secp256k1` (>= 0.2.1 for its ecadd modular-subtraction fix) for
//! the one operation no syscall provides, point addition — because k256's
//! curve arithmetic exceeds the SBF stack-frame limits at runtime. Same
//! math, different engine; the k256 cross-check tests prove the two
//! implementations agree.

use arm_core::aggregation_instance::{ActionAggregated, AggregationInstance};
use arm_core::delta_proof::DeltaProof;
use arm_core::transaction::{Delta, Transaction};
use arm_core::utils::words_to_bytes;
use solana_program::keccak::hashv;
use solana_program::secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Secp256k1, Secp256k1Point, UncompressedPoint};

use crate::error::SolanaArmError;

/// Scalar value 2 as a big-endian 32-byte array, used for EC point doubling.
const SCALAR_TWO: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};

/// Collect the action-tree roots of the aggregation instance as 32-byte
/// arrays, in action order.
///
/// This produces the same byte sequence as
/// [`AggregationInstance::delta_msg`], but as separate 32-byte chunks
/// suitable for Solana's `hashv` syscall: `hashv` concatenates its inputs
/// before hashing, so `hashv(collect_roots(instance))` equals
/// `Keccak-256(instance.delta_msg())`.
pub fn collect_roots(instance: &AggregationInstance) -> Vec<[u8; 32]> {
    instance
        .actions
        .iter()
        .map(|action| action.action_tree_root.into())
        .collect()
}

/// Compute the delta message hash = Keccak-256(concatenated roots) using the
/// Solana syscall.
pub fn compute_delta_msg_hash(roots: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
    hashv(&refs).to_bytes()
}

/// Parse an action's delta coordinates and return them as an UncompressedPoint.
///
/// Delta coordinates are secp256k1 field elements stored as `[u32; 8]` in the
/// aggregation instance, created from big-endian `[u8; 32]` bytes by core's
/// native-endian `words_to_bytes`/`bytes_to_words` pair; reading them back the
/// same way recovers the original big-endian bytes the curve arithmetic wants.
///
/// The curve equation check (y² = x³ + 7 mod p) is intentionally omitted here.
/// The delta coordinates come from a Groth16-verified aggregation instance —
/// the compliance circuit guarantees they are valid secp256k1 points.
fn parse_delta_point(action: &ActionAggregated) -> UncompressedPoint {
    let mut point_bytes = [0u8; 64];
    point_bytes[..32].copy_from_slice(words_to_bytes(&action.delta_x));
    point_bytes[32..].copy_from_slice(words_to_bytes(&action.delta_y));
    UncompressedPoint(point_bytes)
}

/// Accumulate the per-action delta points using EC point addition.
/// Returns the accumulated point, or None if the result is the identity.
pub fn accumulate_deltas(
    instance: &AggregationInstance,
) -> Result<Option<UncompressedPoint>, SolanaArmError> {
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &instance.actions {
        let point = parse_delta_point(action);

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

/// Verify a transaction's delta proof against its aggregation instance using
/// Solana syscalls.
///
/// Accepts and rejects exactly the transactions the host engine accepts
/// and rejects (error variants are finer-grained here): the recovered
/// public key must equal the accumulated delta point (all 64 uncompressed
/// bytes — the EVM adapter's 20-byte address truncation is deliberately
/// not replicated), the signature must be canonical low-s, and an identity
/// delta (no actions, or points cancelling to the identity) is rejected
/// just as the host's `DeltaInstance::new` rejects it.
pub fn verify_delta_proof(tx: &Transaction) -> Result<(), SolanaArmError> {
    let instance = crate::journal::require_aggregation(tx)?;

    let proof = match &tx.delta_proof {
        Delta::Proof(proof) => proof,
        Delta::Witness(_) => return Err(SolanaArmError::ExpectedDeltaProof),
    };

    verify_delta_proof_with_instance(proof, instance)
}

/// [`verify_delta_proof`] over an already-extracted instance.
pub fn verify_delta_proof_with_instance(
    proof: &DeltaProof,
    instance: &AggregationInstance,
) -> Result<(), SolanaArmError> {
    // Reject malleable signatures. Construction already bounds the recovery
    // id and the scalar ranges; the low-s rule is core's shared byte logic.
    proof
        .check_low_s()
        .map_err(|_| SolanaArmError::InvalidDeltaProof)?;

    // Delta message: keccak over the action-tree roots.
    let roots = collect_roots(instance);
    let msg_hash = compute_delta_msg_hash(&roots);

    // Accumulate the per-action delta points.
    let accumulated = accumulate_deltas(instance)?;

    // Recover the public key from the signature.
    let recovered_pubkey = secp256k1_recover(&msg_hash, proof.recovery_id, &proof.signature)
        .map_err(|_| SolanaArmError::DeltaProofVerificationFailed)?;

    // Compare full 64-byte uncompressed public keys directly. The identity
    // has no public key, so it is rejected here just as the host's
    // `DeltaInstance::new` rejects it.
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
    use anoma_rm_risc0::transaction::Aggregation;
    use anoma_rm_risc0::Digest;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    /// Convert a 32-byte array to [u32; 8] — the inverse of the
    /// `words_to_bytes` this module parses delta coordinates with.
    fn words_from_bytes(bytes: [u8; 32]) -> [u32; 8] {
        arm_core::utils::bytes_to_words(&bytes)
            .try_into()
            .expect("32 bytes are 8 words")
    }

    fn point_words(p: &k256::ProjectivePoint) -> ([u32; 8], [u32; 8]) {
        let encoded = p.to_affine().to_encoded_point(false);
        let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();
        (words_from_bytes(x), words_from_bytes(y))
    }

    fn action_with_delta(root: Digest, delta_x: [u32; 8], delta_y: [u32; 8]) -> ActionAggregated {
        ActionAggregated {
            consumed_publics: vec![],
            created_publics: vec![],
            delta_x,
            delta_y,
            action_tree_root: root,
        }
    }

    fn instance_with_actions(actions: Vec<ActionAggregated>) -> AggregationInstance {
        AggregationInstance {
            compliance_key: Digest::default(),
            kind_table_commitment: Digest::default(),
            actions,
        }
    }

    /// Build an aggregated transaction whose single action's delta point is
    /// signing_key's public key, signed by that key.
    fn make_signed_transaction(signing_key: &SigningKey) -> Transaction {
        let vk_point = k256::ProjectivePoint::from(signing_key.verifying_key().as_affine());
        let (delta_x, delta_y) = point_words(&vk_point);

        let root = Digest::from_bytes([0x11; 32]);
        let instance = instance_with_actions(vec![action_with_delta(root, delta_x, delta_y)]);

        // Compute the message hash the same way verify_delta_proof does.
        let msg_hash = compute_delta_msg_hash(&collect_roots(&instance));

        // Sign with k256 (RFC6979; low-s by construction).
        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();

        let mut proof_bytes = [0u8; 65];
        proof_bytes[..64].copy_from_slice(&sig.to_bytes());
        proof_bytes[64] = recid.to_byte() + 27;

        Transaction {
            actions: None,
            delta_proof: Delta::Proof(DeltaProof::from_bytes(&proof_bytes).unwrap()),
            expected_balance: None,
            aggregation: Some(Aggregation {
                proof: vec![],
                instance,
            }),
        }
    }

    #[test]
    fn test_delta_proof() {
        let signing_key = SigningKey::random(&mut OsRng);
        let tx = make_signed_transaction(&signing_key);
        verify_delta_proof(&tx).unwrap();
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        // Replace the instance's delta point with a different key's point.
        let other = SigningKey::random(&mut OsRng);
        let (dx, dy) = point_words(&k256::ProjectivePoint::from(
            other.verifying_key().as_affine(),
        ));
        let agg = tx.aggregation.as_mut().unwrap();
        agg.instance.actions[0].delta_x = dx;
        agg.instance.actions[0].delta_y = dy;
        assert_eq!(verify_delta_proof(&tx), Err(SolanaArmError::DeltaMismatch));
    }

    #[test]
    fn tampered_root_is_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        tx.aggregation.as_mut().unwrap().instance.actions[0].action_tree_root =
            Digest::from_bytes([0x99; 32]);
        // The recovered key changes with the message, so it no longer matches.
        assert_eq!(verify_delta_proof(&tx), Err(SolanaArmError::DeltaMismatch));
    }

    #[test]
    fn empty_instance_is_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let mut tx = make_signed_transaction(&signing_key);
        tx.aggregation.as_mut().unwrap().instance.actions.clear();
        // No actions => identity delta, rejected exactly as the host engine
        // rejects constructing a DeltaInstance from the identity.
        assert_eq!(
            verify_delta_proof(&tx),
            Err(SolanaArmError::DeltaProofVerificationFailed)
        );
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

    /// The syscall path and the host engine must agree end-to-end: a proof
    /// the host engine verifies, this engine verifies, over the same instance.
    #[test]
    fn agrees_with_host_engine() {
        let signing_key = SigningKey::random(&mut OsRng);
        let tx = make_signed_transaction(&signing_key);

        // Host engine (k256): DeltaInstance from the same points and message.
        let instance = tx.aggregation.as_ref().unwrap().instance.clone();
        let points = instance
            .actions
            .iter()
            .map(anoma_rm_risc0::aggregation_instance::delta_projective)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let host_instance =
            anoma_rm_risc0::delta_proof::DeltaInstance::new(&points, instance.delta_msg()).unwrap();
        let Delta::Proof(proof) = &tx.delta_proof else {
            unreachable!()
        };
        anoma_rm_risc0::delta_proof::verify(proof, &host_instance).unwrap();

        // Solana engine (syscalls): same verdict.
        verify_delta_proof(&tx).unwrap();
    }

    #[test]
    fn high_s_malleation_is_rejected() {
        use k256::elliptic_curve::PrimeField;

        let signing_key = SigningKey::random(&mut OsRng);
        let tx = make_signed_transaction(&signing_key);
        let Delta::Proof(proof) = &tx.delta_proof else {
            unreachable!()
        };

        // Negate s and flip the recovery bit: the malleated signature still
        // recovers the same key, so only the low-s rule rejects it.
        let mut bytes = proof.to_bytes();
        let s_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
        let s = k256::Scalar::from_repr(s_bytes.into()).unwrap();
        bytes[32..64].copy_from_slice(&(-s).to_bytes());
        bytes[64] = ((bytes[64] - 27) ^ 1) + 27;
        let malleated = DeltaProof::from_bytes(&bytes).unwrap();

        let instance = &tx.aggregation.as_ref().unwrap().instance;
        assert_eq!(
            verify_delta_proof_with_instance(&malleated, instance),
            Err(SolanaArmError::InvalidDeltaProof)
        );
    }

    // =========================================================================
    // Point arithmetic (accumulate_deltas) cross-checked against k256
    // =========================================================================

    fn g() -> k256::ProjectivePoint {
        k256::ProjectivePoint::GENERATOR
    }

    fn instance_with_delta_points(points: &[k256::ProjectivePoint]) -> AggregationInstance {
        instance_with_actions(
            points
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let (dx, dy) = point_words(p);
                    action_with_delta(Digest::from_bytes([i as u8; 32]), dx, dy)
                })
                .collect(),
        )
    }

    #[test]
    fn test_valid_generator_point() {
        let result = accumulate_deltas(&instance_with_delta_points(&[g()]));
        assert!(result.is_ok(), "G must be accepted: {:?}", result.err());
        assert!(result.unwrap().is_some(), "G is not identity");
    }

    #[test]
    fn test_negated_y_is_valid() {
        let result = accumulate_deltas(&instance_with_delta_points(&[-g()]));
        assert!(result.is_ok(), "-G must be accepted: {:?}", result.err());
        assert!(result.unwrap().is_some(), "-G is not identity");
    }

    #[test]
    fn test_point_doubling() {
        let g_point = accumulate_deltas(&instance_with_delta_points(&[g()]))
            .unwrap()
            .unwrap();
        let two_g_point = accumulate_deltas(&instance_with_delta_points(&[g(), g()]))
            .unwrap()
            .unwrap();
        assert_ne!(
            g_point.0, two_g_point.0,
            "2G must have different coordinates than G"
        );
        // Cross-check against k256's 2G.
        let (x2, y2) = point_words(&(g() + g()));
        let expected = parse_delta_point(&action_with_delta(Digest::default(), x2, y2));
        assert_eq!(two_g_point.0, expected.0, "doubling must match k256");
    }

    #[test]
    fn test_inverse_points_cancel() {
        let result = accumulate_deltas(&instance_with_delta_points(&[g(), -g()]));
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

    /// The accumulation must produce the same result as k256 for a chain of
    /// distinct points: G + 2G + 3G = 6G.
    #[test]
    fn test_accumulation_matches_k256() {
        let two_g = g() + g();
        let three_g = two_g + g();
        let six_g = g() + two_g + three_g;

        let accumulated = accumulate_deltas(&instance_with_delta_points(&[g(), two_g, three_g]))
            .unwrap()
            .unwrap();

        let (x6, y6) = point_words(&six_g);
        let expected = parse_delta_point(&action_with_delta(Digest::default(), x6, y6));
        assert_eq!(accumulated.0, expected.0, "accumulation must match k256");
    }
}
