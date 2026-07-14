use arm::{aggregation::batch::BatchAggregation, transaction::generate_test_transaction};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const ACTION_COUNTS: &[usize] = &[1, 2, 4];

fn bench_batch_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_aggregation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    for &n in ACTION_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, &n| {
            b.iter_with_setup(
                || generate_test_transaction(n),
                |tx| {
                    BatchAggregation::prove_transaction_aggregation(&tx)
                        .expect("batch aggregation proof")
                },
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_batch_aggregation);
criterion_main!(benches);
