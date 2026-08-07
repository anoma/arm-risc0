//! Generates an aggregated ARM transaction and writes it to disk, so a target
//! chain adapter can convert it into a chain transaction and settle it.
//!
//! The transaction is built with the [`Tester`] of `anoma-rm-risc0-test-app`
//! and aggregated into a **Groth16** proof: it is the only receipt type
//! `encode_seal` accepts, and the only one an EVM verifier does.
//!
//! Nothing here touches the `arm` crate, so the circuits — and with them the
//! verifying keys the settling contract pins — stay exactly as checked in.
//!
//! ```text
//! cargo run -p anoma-rm-risc0-tx-gen --release --features cuda,bonsai,prove -- 1:1
//! ```
//!
//! Each argument is one action, written `<consumed>:<created>`; the default is
//! a single `1:1` action. The output directory is `$ARM_TX_OUT_DIR`, defaulting
//! to the workspace `target/`.

use anoma_rm_risc0::aggregation_instance::AggregationInstance;
use anoma_rm_risc0::constants::{
    global_kind_table_hash, BATCH_AGGREGATION_VK, COMPLIANCE_VK, PADDING_LOGIC_VK,
};
use anoma_rm_risc0::proving_system::{encode_seal, instance_to_journal, ProofType};
use anoma_rm_risc0::transaction::Transaction;
use anoma_rm_risc0::Digest;
use anoma_rm_risc0_test_app::{Tester, TEST_LOGIC_VK};
use anyhow::Context;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let shape = parse_shape(std::env::args().skip(1))?;
    let label = shape
        .iter()
        .map(|(consumed, created)| format!("{consumed}x{created}"))
        .collect::<Vec<_>>()
        .join("_");

    println!("generating {} action(s): {label}", shape.len());
    match std::env::var("BONSAI_API_URL") {
        Ok(url) => println!("proving remotely on {url}"),
        Err(_) => println!("proving locally (set BONSAI_API_URL + BONSAI_API_KEY for Bonsai)"),
    }

    let mut tx = Tester::default()
        .generate_test_transaction(&shape)
        .map_err(|err| anyhow::anyhow!("failed to generate the transaction: {err:?}"))?;

    println!("aggregating (Groth16 — the long pole)...");
    tx.aggregate(ProofType::Groth16)
        .map_err(|err| anyhow::anyhow!("aggregation failed: {err:?}"))?;

    tx.verify().map_err(|err| {
        anyhow::anyhow!("the aggregated transaction failed verification: {err:?}")
    })?;

    // Persist before reporting: the proof cost minutes and nothing below is
    // worth losing it to.
    let path = write_transaction(&tx, &format!("transaction_{label}"))?;

    let aggregation = tx.aggregation.as_ref().context("aggregation must be set")?;
    report(&aggregation.instance, &aggregation.proof)?;
    println!("\nwrote {}", path.display());

    Ok(())
}

/// Parses `<consumed>:<created>` arguments into one entry per action,
/// defaulting to a single `1:1` action.
fn parse_shape(args: impl Iterator<Item = String>) -> anyhow::Result<Vec<(u32, u32)>> {
    let shape = args
        .map(|arg| {
            let (consumed, created) = arg
                .split_once(':')
                .with_context(|| format!("expected `<consumed>:<created>`, got `{arg}`"))?;
            Ok((
                consumed.parse().context("invalid consumed count")?,
                created.parse().context("invalid created count")?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(if shape.is_empty() {
        vec![(1, 1)]
    } else {
        shape
    })
}

/// Writes the transaction to `$ARM_TX_OUT_DIR`, defaulting to the workspace
/// `target/`, and returns the path it landed at.
fn write_transaction(tx: &Transaction, name: &str) -> anyhow::Result<PathBuf> {
    let dir = std::env::var("ARM_TX_OUT_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir).context("failed to create the output directory")?;

    let path = dir.join(format!("{name}.bin"));
    let bytes = bincode::serialize(tx).context("failed to serialize the transaction")?;
    std::fs::write(&path, &bytes).context("failed to write the transaction")?;
    println!("\n{} bytes serialized", bytes.len());

    Ok(path)
}

/// Prints what a settling contract has to agree with: the keys it pins, the
/// kind table it stores, and the tags the transaction adds to its state.
fn report(instance: &AggregationInstance, proof: &[u8]) -> anyhow::Result<()> {
    let seal = encode_seal(proof)
        .map_err(|err| anyhow::anyhow!("the aggregation proof is not Groth16: {err:?}"))?;
    let journal = instance_to_journal(instance)
        .map_err(|err| anyhow::anyhow!("failed to encode the journal: {err:?}"))?;

    println!("\nthe verifier must pin");
    println!("  batch aggregation vk:  {}", hex32(&BATCH_AGGREGATION_VK));
    println!("  compliance vk:         {}", hex32(&COMPLIANCE_VK));
    println!(
        "  kind table commitment: {}",
        hex32(&instance.kind_table_commitment)
    );
    if global_kind_table_hash() != Some(&instance.kind_table_commitment) {
        println!("  (warning: differs from the loaded global kind table)");
    }

    println!("\nresource logics used");
    println!("  test logic:            {}", hex32(&TEST_LOGIC_VK));
    println!("  padding logic:         {}", hex32(&PADDING_LOGIC_VK));

    println!("\nproof");
    println!("  seal selector:         0x{}", hex::encode(&seal[..4]));
    println!("  seal bytes:            {}", seal.len());
    println!(
        "  journal digest:        0x{}",
        hex::encode(Sha256::digest(&journal))
    );
    println!("  journal bytes:         {}", journal.len());

    for (index, action) in instance.actions.iter().enumerate() {
        println!("\naction {index}");
        println!(
            "  action tree root:      {}",
            hex32(&action.action_tree_root)
        );
        for consumed in &action.consumed_publics {
            println!(
                "  nullifier:             {}",
                hex32(&consumed.resource_nullifier)
            );
            println!(
                "    commitment tree root:{}",
                hex32(&consumed.commitment_tree_root)
            );
        }
        for created in &action.created_publics {
            println!(
                "  commitment:            {}",
                hex32(&created.resource_commitment)
            );
        }
    }

    Ok(())
}

fn hex32(digest: &Digest) -> String {
    format!("0x{}", hex::encode(digest.as_bytes()))
}
