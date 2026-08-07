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
//! The arguments give the [`Shape`] of the transaction — a consumed and a
//! created count per action — defaulting to a single `1:1` action. The output
//! directory is `$ARM_TX_OUT_DIR`, defaulting to the workspace `target/`.

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
use std::fmt;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let shape = Shape::from_args(std::env::args().skip(1))?;
    let label = shape.to_string();

    println!("generating {} action(s): {label}", shape.actions.len());
    match std::env::var("BONSAI_API_URL") {
        Ok(url) => println!("proving remotely on {url}"),
        Err(_) => println!("proving locally (set BONSAI_API_URL + BONSAI_API_KEY for Bonsai)"),
    }

    let mut tx = Tester::default()
        .generate_test_transaction(&shape.as_pairs())
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

/// The resource counts of a single action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActionShape {
    consumed: u32,
    created: u32,
}

impl fmt::Display for ActionShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{}", self.consumed, self.created)
    }
}

/// The shape of a whole transaction: one [`ActionShape`] per action.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Shape {
    actions: Vec<ActionShape>,
}

impl Shape {
    /// A single action consuming and creating one resource.
    fn one_to_one() -> Self {
        Self {
            actions: vec![ActionShape {
                consumed: 1,
                created: 1,
            }],
        }
    }

    /// Reads the shape off the command line, defaulting to [`Self::one_to_one`]
    /// when no arguments are given.
    ///
    /// Counts are taken in order and paired up, so every punctuation style that
    /// separates them works — `2:2 2:2`, `2,2 2,2` and `'[(2,2),(2,2)]'` all
    /// describe the same two actions. Quote the bracketed form; a shell reads
    /// its parentheses otherwise.
    fn from_args(args: impl Iterator<Item = String>) -> anyhow::Result<Self> {
        let joined = args.collect::<Vec<_>>().join(" ");
        if joined.trim().is_empty() {
            return Ok(Self::one_to_one());
        }

        let counts = joined
            .split(|c: char| !c.is_ascii_digit())
            .filter(|field| !field.is_empty())
            .map(|field| {
                field
                    .parse::<u32>()
                    .with_context(|| format!("`{field}` is not a resource count"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        anyhow::ensure!(
            !counts.is_empty() && counts.len() % 2 == 0,
            "expected a consumed and a created count per action, e.g. `2:2 2:2`, got `{joined}`"
        );

        let shape = Self {
            actions: counts
                .chunks_exact(2)
                .map(|pair| ActionShape {
                    consumed: pair[0],
                    created: pair[1],
                })
                .collect(),
        };
        shape.validate()?;

        Ok(shape)
    }

    /// Rejects shapes the tester cannot satisfy, before minutes of proving go
    /// into a transaction that cannot verify.
    ///
    /// Every resource it builds carries quantity 1 under a single kind, so the
    /// transaction delta cancels exactly when as many resources are created as
    /// consumed — across the transaction, not within each action, since the
    /// deltas of all actions are summed. An action must still consume
    /// something: created nonces are derived from the consumed nullifiers.
    fn validate(&self) -> anyhow::Result<()> {
        for (index, action) in self.actions.iter().enumerate() {
            anyhow::ensure!(
                action.consumed > 0,
                "action {index} ({action}) consumes nothing, but its created nonces would have to \
                 derive from the nullifiers of consumed resources"
            );
        }

        let consumed: u32 = self.actions.iter().map(|action| action.consumed).sum();
        let created: u32 = self.actions.iter().map(|action| action.created).sum();
        anyhow::ensure!(
            consumed == created,
            "unbalanced shape: {consumed} consumed against {created} created. Every resource has \
             quantity 1 under one kind, so the totals must match for the delta proof to verify — \
             individual actions may still be lopsided, as in `3:2 1:2`"
        );

        Ok(())
    }

    /// The representation [`Tester::generate_test_transaction`] takes.
    fn as_pairs(&self) -> Vec<(u32, u32)> {
        self.actions
            .iter()
            .map(|action| (action.consumed, action.created))
            .collect()
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let actions: Vec<String> = self.actions.iter().map(ActionShape::to_string).collect();
        write!(f, "{}", actions.join("_"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(args: &[&str]) -> anyhow::Result<Shape> {
        Shape::from_args(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn from_args_defaults_to_a_single_one_to_one_action() {
        assert_eq!(shape(&[]).unwrap(), Shape::one_to_one());
        assert_eq!(shape(&[""]).unwrap(), Shape::one_to_one());
    }

    #[test]
    fn from_args_reads_one_action_per_argument() {
        let expected = Shape {
            actions: vec![
                ActionShape {
                    consumed: 2,
                    created: 3,
                },
                ActionShape {
                    consumed: 3,
                    created: 2,
                },
            ],
        };

        assert_eq!(shape(&["2:3", "3:2"]).unwrap(), expected);
    }

    /// Every punctuation style describes the same shape, so a Rust literal
    /// pasted from a test reads the same as the colon form.
    #[test]
    fn from_args_accepts_the_punctuation_styles_interchangeably() {
        let expected = shape(&["2:2", "2:2"]).unwrap();

        assert_eq!(shape(&["2,2", "2,2"]).unwrap(), expected);
        assert_eq!(shape(&["(2,2)", "(2,2)"]).unwrap(), expected);
        assert_eq!(shape(&["[(2,2),(2,2)]"]).unwrap(), expected);
        assert_eq!(shape(&["[(2,", "2),", "(2,", "2)]"]).unwrap(), expected);
    }

    #[test]
    fn from_args_errors_on_an_unpaired_count() {
        assert!(shape(&["2:2", "3"]).is_err());
    }

    /// The delta sums over the whole transaction, so only the totals have to
    /// match — this is the shape `test_transaction` proves.
    #[test]
    fn from_args_accepts_lopsided_actions_that_cancel_out() {
        assert!(shape(&["2:1", "1:2"]).is_ok());
        assert!(shape(&["3:2", "1:2"]).is_ok());
    }

    #[test]
    fn from_args_rejects_a_shape_that_consumes_more_than_it_creates() {
        let error = shape(&["3:2", "1:0"]).unwrap_err().to_string();

        assert!(error.contains("4 consumed against 2 created"), "{error}");
    }

    #[test]
    fn from_args_rejects_an_action_consuming_nothing() {
        assert!(shape(&["0:1"]).is_err());
    }

    #[test]
    fn from_args_errors_on_a_count_that_is_not_a_number() {
        assert!(shape(&["two:two"]).is_err());
    }

    #[test]
    fn display_names_the_output_file_after_the_shape() {
        assert_eq!(shape(&["1:1"]).unwrap().to_string(), "1x1");
        assert_eq!(shape(&["[(2,2),(2,2)]"]).unwrap().to_string(), "2x2_2x2");
    }
}
