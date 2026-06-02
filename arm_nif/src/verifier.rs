//! NIFs verifying and reading arm-risc0 resource machine transactions.
//!
//! Every entry point takes a bincode-encoded `anoma_rm_risc0::transaction::Transaction`
//! as an opaque binary

use crate::error::ArmNifError;
use anoma_rm_risc0::{
    Digest,
    action::Action,
    compliance::ComplianceInstance,
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob},
    transaction::Transaction,
};
use bincode::Options;
use rustler::{Binary, Env, NifResult, OwnedBinary};
use std::collections::BTreeSet;

/// Upper bound on a decoded transaction
const MAX_TX_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

/// Decode a bincode-encoded `Transaction`
fn decode_tx(tx_bytes: &[u8]) -> Result<Transaction, ArmNifError> {
    Ok(bincode::options()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_TX_BYTES)
        .deserialize(tx_bytes)?)
}

/// Copy bytes into a freshly-allocated Erlang binary
fn to_bin<'a>(env: Env<'a>, bytes: &[u8]) -> Binary<'a> {
    let mut bin = OwnedBinary::new(bytes.len()).expect("OwnedBinary allocation failed");
    bin.as_mut_slice().copy_from_slice(bytes);
    bin.release(env)
}

/// A risc0 `Digest` as a fixed 32-byte array
fn digest32(d: &Digest) -> [u8; 32] {
    d.as_bytes()
        .try_into()
        .expect("a risc0 Digest is always 32 bytes")
}

/// Decode the transaction and collect every action's compliance instance
fn instances(tx_bytes: &[u8]) -> Result<Vec<ComplianceInstance>, ArmNifError> {
    decode_tx(tx_bytes)?
        .actions
        .iter()
        .map(|a| a.compliance_unit.get_instance().map_err(ArmNifError::from))
        .collect()
}

/// The four payload categories (resource, discovery, external, application) as
/// `(blob_words, deletion_criterion)` lists
type AppDataBlobs = (
    Vec<(Vec<u32>, u32)>,
    Vec<(Vec<u32>, u32)>,
    Vec<(Vec<u32>, u32)>,
    Vec<(Vec<u32>, u32)>,
);

fn app_data_blobs(ad: &AppData) -> AppDataBlobs {
    let conv = |bs: &[ExpirableBlob]| -> Vec<(Vec<u32>, u32)> {
        bs.iter()
            .map(|b| (b.blob.clone(), b.deletion_criterion))
            .collect()
    };
    (
        conv(&ad.resource_payload),
        conv(&ad.discovery_payload),
        conv(&ad.external_payload),
        conv(&ad.application_payload),
    )
}

fn app_data_for_tag(action: &Action, tag: &Digest) -> Result<AppDataBlobs, ArmNifError> {
    let input = action
        .logic_verifier_inputs
        .iter()
        .find(|i| &i.tag == tag)
        .ok_or(ArmError::TagNotFound)?;
    Ok(app_data_blobs(&input.app_data))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_transaction(tx_bytes: Binary) -> NifResult<bool> {
    Ok(decode_tx(tx_bytes.as_slice())?.verify().is_ok())
}

/// Decode + verify a transaction in one pass and return the effects needed for
/// global checks and storage
#[rustler::nif(schedule = "DirtyCpu")]
fn verify_and_extract<'a>(
    env: Env<'a>,
    tx_bytes: Binary<'a>,
) -> NifResult<(
    Vec<(Binary<'a>, AppDataBlobs)>,
    Vec<(Binary<'a>, AppDataBlobs)>,
    Vec<Binary<'a>>,
)> {
    let tx = decode_tx(tx_bytes.as_slice())?;
    let mut consumed = Vec::new();
    let mut created = Vec::new();
    let mut roots: BTreeSet<[u8; 32]> = BTreeSet::new();
    for action in &tx.actions {
        let ci = action
            .compliance_unit
            .get_instance()
            .map_err(ArmNifError::from)?;
        for c in &ci.consumed_publics {
            let ad = app_data_for_tag(action, &c.resource_nullifier)?;
            consumed.push((to_bin(env, c.resource_nullifier.as_bytes()), ad));
            roots.insert(digest32(&c.commitment_tree_root));
        }
        for c in &ci.created_publics {
            let ad = app_data_for_tag(action, &c.resource_commitment)?;
            created.push((to_bin(env, c.resource_commitment.as_bytes()), ad));
        }
    }

    tx.verify().map_err(ArmNifError::from)?;

    let roots = roots.iter().map(|r| to_bin(env, r)).collect();
    Ok((consumed, created, roots))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_nullifiers<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    Ok(instances(tx_bytes.as_slice())?
        .iter()
        .flat_map(|ci| {
            ci.consumed_publics
                .iter()
                .map(|c| to_bin(env, c.resource_nullifier.as_bytes()))
        })
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_commitments<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    Ok(instances(tx_bytes.as_slice())?
        .iter()
        .flat_map(|ci| {
            ci.created_publics
                .iter()
                .map(|c| to_bin(env, c.resource_commitment.as_bytes()))
        })
        .collect())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn transaction_roots<'a>(env: Env<'a>, tx_bytes: Binary<'a>) -> NifResult<Vec<Binary<'a>>> {
    let roots: BTreeSet<[u8; 32]> = instances(tx_bytes.as_slice())?
        .iter()
        .flat_map(|ci| {
            ci.consumed_publics
                .iter()
                .map(|c| digest32(&c.commitment_tree_root))
        })
        .collect();
    Ok(roots.iter().map(|r| to_bin(env, r)).collect())
}
