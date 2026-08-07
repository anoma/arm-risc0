//! Batch-aggregation proof benchmarks.
//!
//! The benchmark measures only outer aggregation proving (Groth16).  It
//! prepares the compliance and logic receipts (Succinct) once, outside
//! Criterion's measurement loop, then aggregates a fresh clone of that
//! transaction for every sample.
//!
//! Run:
//!
//! ```sh
//! cargo bench --manifest-path arm_circuits/batch_aggregation/Cargo.toml --features prove,bonsai,cuda
//! ```
//!
//! For a fast check of witness assembly, set `RISC0_DEV_MODE=1`.
//!
//! Timing parameters can be overridden at runtime:
//! - `BENCH_WARMUP_SECS`  — warm-up duration per group (default: 30)
//! - `BENCH_MEASURE_SECS` — measurement duration per group (default: 300)
use anoma_rm_risc0::proving_system::ProofType;
use anoma_rm_risc0_test_app::generate_test_transaction;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use std::time::Duration;

/// Number of compliance units per action.  Each compliance unit contributes
/// one consumed and one created resource, so this many compliance receipts
/// and twice as many logic receipts are added to the aggregation assumption set.
const COMPLIANCE_UNITS_PER_ACTION: usize = 2;
const ACTION_COUNTS: &[usize] = &[1, 2, 4];

fn env_duration(var: &str, default_secs: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

/// Builds a fully-proved transaction fixture with `action_count` actions.
/// Base proofs use Succinct (STARK); only the outer aggregation uses Groth16.
/// This runs outside the measurement loop; its cost is not attributed to the
/// aggregation proof.
fn make_transaction(action_count: usize) -> anoma_rm_risc0::transaction::Transaction {
    generate_test_transaction(action_count, COMPLIANCE_UNITS_PER_ACTION, ProofType::Succinct)
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_aggregation");
    // SamplingMode::Flat runs exactly `sample_size` iterations rather than
    // interpolating, which is correct for slow ZK operations where a single
    // iteration can take tens of seconds.
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.warm_up_time(env_duration("BENCH_WARMUP_SECS", 30));
    group.measurement_time(env_duration("BENCH_MEASURE_SECS", 300));

    for &action_count in ACTION_COUNTS {
        // Deliberately outside `iter_batched_ref`: base proof generation is a
        // separate cost and must not be attributed to the outer aggregation.
        let transaction = make_transaction(action_count);
        group.bench_with_input(
            BenchmarkId::new("prove", action_count),
            &transaction,
            |b, transaction| {
                // PerIteration: one fresh clone per measurement sample.
                // Avoids pre-allocating a batch of large proof objects and
                // gives precise per-call timing for expensive ZK operations.
                b.iter_batched_ref(
                    || transaction.clone(),
                    |transaction| {
                        transaction
                            .aggregate(ProofType::Groth16)
                            .expect("aggregation proof must succeed");
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_prove);
criterion_main!(benches);
