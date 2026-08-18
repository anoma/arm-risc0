//! Aggregation journal binding via Solana syscalls.

use anoma_rm_risc0::aggregation_instance::AggregationInstance;
use anoma_rm_risc0::transaction::Transaction;
use solana_program::hash::hash;

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
/// [`AggregationInstance::to_journal`], so every field the adapter acts on
/// is bound by the proof.
pub fn aggregation_journal_digest(instance: &AggregationInstance) -> [u8; 32] {
    hash(&instance.to_journal()).to_bytes()
}
