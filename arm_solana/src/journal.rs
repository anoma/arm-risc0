//! Aggregation journal binding via Solana syscalls.

use arm_core::aggregation_instance::AggregationInstance;
use arm_core::transaction::Transaction;
use solana_sha256_hasher::hash;

use crate::error::SolanaArmError;

/// Returns the transaction's aggregation instance — the only proof-backed
/// source of settlement data an on-chain verifier may trust.
///
/// A `Transaction` is a plain deserializable struct, so nothing stops a
/// crafted one from carrying both `actions` and `aggregation`. Accepting a
/// transaction that also carries `actions` would leave an unverified,
/// attacker-controlled shadow copy of the settlement data on the wire, so
/// the ambiguous shape is rejected outright.
pub fn require_aggregation(tx: &Transaction) -> Result<&AggregationInstance, SolanaArmError> {
    let instance = &tx
        .aggregation
        .as_ref()
        .ok_or(SolanaArmError::MissingAggregation)?
        .instance;
    if tx.actions.is_some() {
        return Err(SolanaArmError::AmbiguousTransaction);
    }
    Ok(instance)
}

/// Computes the sha256 digest of the aggregation journal via the Solana
/// syscall — the Groth16 public-input binding for the batch aggregation
/// proof. The journal bytes are re-derived from the instance with
/// [`AggregationInstance::to_journal`], so every field the verifier acts on
/// is bound by the proof.
pub fn aggregation_journal_digest(instance: &AggregationInstance) -> [u8; 32] {
    hash(&instance.to_journal()).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arm_core::delta_proof::DeltaWitness;
    use arm_core::transaction::{Aggregation, Delta};
    use arm_core::Digest;

    fn instance() -> AggregationInstance {
        AggregationInstance {
            compliance_key: Digest::from_bytes([0xC0; 32]),
            kind_table_commitment: Digest::from_bytes([0xC1; 32]),
            actions: vec![],
        }
    }

    fn witness_delta() -> Delta {
        Delta::Witness(DeltaWitness::from_bytes(&[7u8; 32]).unwrap())
    }

    #[test]
    fn accepts_aggregated_only() {
        let tx = Transaction {
            actions: None,
            delta_proof: witness_delta(),
            expected_balance: None,
            aggregation: Some(Aggregation {
                proof: vec![],
                instance: instance(),
            }),
        };
        assert!(require_aggregation(&tx).is_ok());
    }

    #[test]
    fn rejects_unaggregated() {
        let tx = Transaction {
            actions: Some(vec![]),
            delta_proof: witness_delta(),
            expected_balance: None,
            aggregation: None,
        };
        assert_eq!(
            require_aggregation(&tx).err(),
            Some(SolanaArmError::MissingAggregation)
        );
    }

    #[test]
    fn rejects_ambiguous_both_representations() {
        let tx = Transaction {
            actions: Some(vec![]),
            delta_proof: witness_delta(),
            expected_balance: None,
            aggregation: Some(Aggregation {
                proof: vec![],
                instance: instance(),
            }),
        };
        assert_eq!(
            require_aggregation(&tx).err(),
            Some(SolanaArmError::AmbiguousTransaction)
        );
    }

    /// The digest is sha256 of the 68-byte journal (compliance key, kind-table
    /// commitment, zero actions): the expected bytes come from Python's
    /// hashlib over that journal, an implementation independent of the
    /// engine this crate's host build falls back to.
    #[test]
    fn digest_is_sha256_of_journal_golden() {
        let expected = [
            0x45, 0xd5, 0x2a, 0xbe, 0xe4, 0x43, 0xcc, 0x8d, 0x50, 0x31, 0x59, 0x26, 0x93, 0x79,
            0xf8, 0x8f, 0x7f, 0x1b, 0x09, 0x89, 0x11, 0x29, 0xeb, 0x81, 0x44, 0xce, 0xba, 0x1f,
            0x57, 0x89, 0x63, 0xdf,
        ];
        assert_eq!(aggregation_journal_digest(&instance()), expected);
    }
}
