use arm::{aggregation::sequential::SequentialAggregation, transaction::generate_test_transaction};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const ACTION_COUNTS: &[usize] = &[1, 2, 4, 8];

fn bench_sequential_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_aggregation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    for &n in ACTION_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let tx = generate_test_transaction(n);
                    let (instances, proofs) = SequentialAggregation::transaction_transcript(&tx)
                        .expect("transcript");
                    (instances, proofs.expect("step proofs"))
                },
                |(instances, proofs)| {
                    SequentialAggregation::prove_transcript_aggregation(&instances, &proofs)
                        .expect("aggregation proof")
                },
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sequential_aggregation);
criterion_main!(benches);
