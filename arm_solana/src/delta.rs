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
}
