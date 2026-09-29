//! Batch-aggregation proof benchmarks.
//!
//! The benchmark measures only outer aggregation proving.  It prepares the
//! compliance and logic receipts once, outside Criterion's measurement loop,
//! then aggregates a fresh clone of that transaction for every sample.
//!
//! Each action count is benchmarked at two segment sizes (po2=21 default,
//! po2=22) to measure the effect of larger segments on prover throughput.
//!
//! Run:
//!
//! ```sh
//! cargo bench --manifest-path arm_circuits/batch_aggregation/Cargo.toml --features prove,bonsai,cuda
//! ```
//!
//! Run the EVM ABI-encoded journal variant:
//!
//! ```sh
//! cargo bench --manifest-path arm_circuits/batch_aggregation/Cargo.toml --features prove,bonsai,cuda,abi_encoding
//! ```
//!
//! For a fast check of witness assembly, set `RISC0_DEV_MODE=1`.
//!
//! Timing parameters can be overridden at runtime:
//! - `BENCH_WARMUP_SECS`  — warm-up duration per group (default: 30)
//! - `BENCH_MEASURE_SECS` — measurement duration per group (default: 300)
use anoma_rm_risc0::proving_system::{JournalEncoding, ProofType};
use anoma_rm_risc0::transaction;
use anoma_rm_risc0_test_app::Tester;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use std::time::Duration;

/// Each action has this many consumed and created resources.  Consequently,
/// every action contributes one compliance receipt and four logic receipts to
/// the aggregation guest's assumption set.
const RESOURCES_PER_ACTION: (u32, u32) = (2, 2);
const ACTION_COUNTS: &[usize] = &[1, 2, 4];
const SEGMENT_PO2S: &[u32] = &[21, 22];

const PROOF_TYPE: ProofType = ProofType::Groth16;

#[cfg(feature = "abi_encoding")]
const JOURNAL_ENCODING: JournalEncoding = JournalEncoding::Abi;
#[cfg(not(feature = "abi_encoding"))]
const JOURNAL_ENCODING: JournalEncoding = JournalEncoding::Risc0Serde;

fn env_duration(var: &str, default_secs: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

/// Builds a fully-proved transaction fixture with `action_count` actions.
/// This runs outside the measurement loop; its cost is not attributed to the
/// aggregation proof.
fn make_transaction(action_count: usize) -> anoma_rm_risc0::transaction::Transaction {
    let actions = vec![RESOURCES_PER_ACTION; action_count];
    Tester::default()
        .generate_test_transaction(&actions)
        .expect("benchmark fixture proofs must be valid")
}

fn bench_prove(c: &mut Criterion) {
    let encoding_label = match JOURNAL_ENCODING {
        JournalEncoding::Abi => "abi_encoding",
        JournalEncoding::Risc0Serde => "default",
    };
    let mut group = c.benchmark_group(format!("batch_aggregation/{encoding_label}"));
    // SamplingMode::Flat runs exactly `sample_size` iterations rather than
    // interpolating, which is correct for slow ZK operations where a single
    // iteration can take tens of seconds.
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.warm_up_time(env_duration("BENCH_WARMUP_SECS", 30));
    group.measurement_time(env_duration("BENCH_MEASURE_SECS", 300));

    for &po2 in SEGMENT_PO2S {
        for &action_count in ACTION_COUNTS {
            // Deliberately outside `iter_batched_ref`: base proof generation is a
            // separate cost and must not be attributed to the outer aggregation.
            let transaction = make_transaction(action_count);
            group.bench_with_input(
                BenchmarkId::new(format!("prove/po2={po2}"), action_count),
                &(transaction, po2),
                |b, (transaction, po2)| {
                    // PerIteration: one fresh clone per measurement sample.
                    // Avoids pre-allocating a batch of large proof objects and
                    // gives precise per-call timing for expensive ZK operations.
                    b.iter_batched_ref(
                        || transaction.clone(),
                        |transaction| {
                            transaction::aggregate(
                                transaction,
                                PROOF_TYPE,
                                JOURNAL_ENCODING,
                                *po2,
                            )
                            .expect("aggregation proof must succeed");
                        },
                        criterion::BatchSize::PerIteration,
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_prove);
criterion_main!(benches);
