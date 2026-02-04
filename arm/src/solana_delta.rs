//! Delta proof verification for Solana on-chain programs.
//!
//! Uses Solana syscalls (hashv, secp256k1_recover) and solana-secp256k1 for
//! EC point arithmetic instead of k256, which exceeds SBF stack frame limits.
//!
//! Algorithm:
//! 1. Collect tags (nullifiers and commitments) in compliance unit order
//! 2. Compute verifying key = SHA-256(tags) using Solana syscall
//! 3. Accumulate delta points via secp256k1 EC point addition
//! 4. Verify ECDSA signature using Solana secp256k1_recover syscall

use crate::error::ArmError;
use crate::transaction::{Delta, Transaction};

use dashu::integer::UBig;
use solana_program::hash::hashv;
use solana_program::secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Curve, Secp256k1Point, UncompressedPoint};

/// Collect tags (nullifiers and commitments) in compliance unit order.
/// Returns tags as 32-byte arrays in the order: [nf0, cm0, nf1, cm1, ...]
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

/// Convert [u32; 8] words to [u8; 32] bytes (bytemuck cast, matching arm-risc0 convention).
fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    *bytemuck::cast_ref(words)
}

/// Parse delta coordinates from a compliance instance and return as an UncompressedPoint.
///
/// All compliance units must provide valid secp256k1 curve points. The point (0, 0)
/// is NOT on the curve and will error - the identity point (point at infinity) has
/// no valid affine representation.
fn parse_delta_point(
    x_words: &[u32; 8],
    y_words: &[u32; 8],
) -> Result<UncompressedPoint, ArmError> {
    let x_bytes = words_to_bytes(x_words);
    let y_bytes = words_to_bytes(y_words);

    // solana-secp256k1 does not validate that points lie on the curve.
    // We must check the curve equation manually: y² ≡ x³ + 7 (mod p)
    let p = UBig::from_be_bytes(&Curve::P);
    let x = UBig::from_be_bytes(&x_bytes);
    let y = UBig::from_be_bytes(&y_bytes);

    let y_squared = y.sqr() % &p;
    let x_cubed_plus_7 = (x.cubic() + UBig::from_word(7)) % &p;

    if y_squared != x_cubed_plus_7 {
        return Err(ArmError::DeltaPointNotOnCurve);
    }

    // Point is valid - construct UncompressedPoint
    let mut point_bytes = [0u8; 64];
    point_bytes[..32].copy_from_slice(&x_bytes);
    point_bytes[32..].copy_from_slice(&y_bytes);
    Ok(UncompressedPoint(point_bytes))
}

/// Accumulate delta points from all compliance instances using EC point addition.
/// Returns the accumulated point as an UncompressedPoint, or None if the result is the identity.
pub fn accumulate_deltas(tx: &Transaction) -> Result<Option<UncompressedPoint>, ArmError> {
    // UncompressedPoint has no identity representation, so we track it with Option.
    let mut accumulated: Option<UncompressedPoint> = None;

    for action in &tx.actions {
        for cu in &action.compliance_units {
            let point = parse_delta_point(&cu.instance.delta_x, &cu.instance.delta_y)?;

            accumulated = match accumulated {
                None => Some(point),
                Some(acc) => {
                    // solana-secp256k1's Add does not handle point doubling (P + P)
                    // or inverse points (P + (-P)). We detect and handle these cases.
                    let x_acc = acc.x();
                    let x_pt = point.x();

                    if x_acc == x_pt {
                        // Same x-coordinate: either doubling or inverse
                        if acc.y() == point.y() {
                            // Point doubling: P + P - use scalar multiplication by 2
                            #[rustfmt::skip]
                            let two: [u8; 32] = [
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2
                            ];
                            Some(
                                Curve::ecmul(&acc, &two)
                                    .map_err(|_| ArmError::DeltaPointNotOnCurve)?,
                            )
                        } else {
                            // Inverse points: P + (-P) = identity
                            None
                        }
                    } else {
                        // Standard case - library's Add is safe here
                        Some(acc + point)
                    }
                }
            };
        }
    }

    Ok(accumulated)
}

/// Convert an uncompressed point to its "address" representation using Solana syscall.
/// address = last 20 bytes of SHA-256(x || y)
fn point_to_address(point: &UncompressedPoint) -> [u8; 20] {
    let hash: [u8; 32] = hashv(&[&point.0]).to_bytes();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Verify the delta proof using Solana syscalls for optimal CU usage.
///
/// The delta proof is an ECDSA signature that proves the transaction is balanced.
/// The signer's public key must correspond to the accumulated delta point.
pub fn verify_delta_proof(tx: &Transaction) -> Result<(), ArmError> {
    // 1. Check delta_proof type FIRST to avoid expensive operations in Witness mode
    let signature_bytes = match &tx.delta_proof {
        Delta::Proof(bytes) => {
            if bytes.len() != 65 {
                return Err(ArmError::InvalidDeltaProof);
            }
            bytes.as_slice()
        }
        Delta::Witness(_) => {
            // Witness mode is not supported - always require a proof
            return Err(ArmError::ExpectedDeltaProof);
        }
    };

    // 2. Collect tags
    let tags = collect_tags(tx);

    // Empty transaction - no delta verification needed
    if tags.is_empty() {
        return Ok(());
    }

    // 3. Compute verifying key (message hash) using Solana syscall
    let verifying_key = compute_verifying_key(&tags);

    // 4. Accumulate delta points
    let accumulated = accumulate_deltas(tx)?;

    // 5. Parse signature (64 bytes) and recovery ID (1 byte)
    let sig_bytes: [u8; 64] = signature_bytes[0..64]
        .try_into()
        .map_err(|_| ArmError::InvalidDeltaProof)?;

    let recid = signature_bytes[64];

    // 6. Recover the public key using Solana syscall (much cheaper than software recovery)
    let recovered_pubkey = secp256k1_recover(&verifying_key, recid, &sig_bytes)
        .map_err(|_| ArmError::DeltaProofVerificationFailed)?;

    // 7. Convert recovered key to address using Solana syscall
    // secp256k1_recover returns 64 bytes (x || y), no 0x04 prefix
    let recovered_hash: [u8; 32] = hashv(&[&recovered_pubkey.0]).to_bytes();
    let recovered_address: [u8; 20] = recovered_hash[12..32].try_into().unwrap();

    // 8. Compare with expected address from accumulated delta
    let expected_address = match accumulated {
        Some(point) => point_to_address(&point),
        None => {
            return Err(ArmError::DeltaProofVerificationFailed);
        }
    };

    if recovered_address != expected_address {
        return Err(ArmError::DeltaMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;
    use crate::compliance::ComplianceInstance;
    use crate::compliance_unit::ComplianceUnit;
    use crate::Digest;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;

    /// Build a Transaction with a single compliance unit whose delta point
    /// matches `signing_key`'s public key, signed by that key.
    fn make_signed_transaction(signing_key: &SigningKey) -> Transaction {
        let vk = k256::ecdsa::VerifyingKey::from(signing_key);
        let encoded = vk.to_encoded_point(false);
        let x_bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let y_bytes: [u8; 32] = encoded.y().unwrap().as_slice().try_into().unwrap();

        let delta_x: [u32; 8] = bytemuck::cast(x_bytes);
        let delta_y: [u32; 8] = bytemuck::cast(y_bytes);

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

        // Compute the message hash (same path as verify_delta_proof)
        let nf_bytes = Digest::default().to_bytes();
        let cm_bytes = Digest::default().to_bytes();
        let msg_hash = compute_verifying_key(&[nf_bytes, cm_bytes]);

        // Sign the message hash with k256
        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();

        let mut proof_bytes = Vec::with_capacity(65);
        proof_bytes.extend_from_slice(&sig.to_bytes());
        proof_bytes.push(recid.to_byte());

        Transaction {
            actions: vec![action],
            delta_proof: Delta::Proof(proof_bytes),
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
}
