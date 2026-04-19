/// Compliance circuit benchmarks.
///
/// Measures wall-clock prove time with two kind-table configurations:
/// - `empty_table`: the circuit falls back to `hash_to_curve` for every resource.
/// - `file_table`:  kind points are pre-computed in `kind_table.json`; the circuit
///                  resolves them via a table lookup, skipping `hash_to_curve`.
///
/// # Running on CPU
///
/// ```sh
/// cargo bench --features prove -p compliance
/// ```
///
/// # Running on GPU (CUDA)
///
/// ```sh
/// cargo bench --features prove,cuda -p compliance
/// ```
///
/// # Fast / dev-mode iteration
///
/// Set `RISC0_DEV_MODE=1` to skip actual proof generation and validate only
/// the witness-assembly logic without the multi-minute prover overhead.
///
/// ```sh
/// RISC0_DEV_MODE=1 cargo bench --features prove -p compliance
/// ```
use anoma_rm_risc0::compliance::{ComplianceWitness, INITIAL_ROOT};
use anoma_rm_risc0::constants::{global_kind_table, init_kind_table_from_file};
use anoma_rm_risc0::merkle_path::MerklePath;
use anoma_rm_risc0::nullifier_key::NullifierKey;
use anoma_rm_risc0::resource::Resource;
use compliance_methods::COMPLIANCE_GUEST_ELF;
use criterion::{criterion_group, criterion_main, Criterion};
use risc0_zkvm::{default_prover, Digest, ExecutorEnv};
use std::time::Duration;

fn do_prove(witness: &ComplianceWitness) {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();
    default_prover().prove(env, COMPLIANCE_GUEST_ELF).unwrap();
}

/// Build a compliance witness whose resources use `logic_ref` and `label_ref`,
/// pulling the current global kind table into the witness.
fn make_witness(logic_ref: Digest, label_ref: Digest) -> ComplianceWitness {
    let nf_key = NullifierKey::default();
    let consumed_resource = Resource {
        logic_ref,
        label_ref,
        quantity: 1,
        value_ref: Digest::default(),
        is_ephemeral: false,
        nonce: [0u8; 32],
        nk_commitment: nf_key.commit(),
        rand_seed: [0u8; 32],
    };
    let nf = consumed_resource.nullifier(&nf_key).unwrap();
    let created_resource = Resource {
        nonce: nf.as_bytes().try_into().unwrap(),
        ..consumed_resource
    };
    ComplianceWitness {
        consumed_resource,
        merkle_path: MerklePath::default(),
        ephemeral_root: *INITIAL_ROOT,
        nf_key,
        created_resource,
        // Scalar::ONE encoded as big-endian 32 bytes
        rcv: [vec![0u8; 31], vec![1u8]].concat(),
        kind_table: global_kind_table().to_vec(),
    }
}

/// Empty kind table: the circuit falls back to `hash_to_curve` for every resource.
fn bench_empty_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance/empty_table");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("prove", |b| {
        b.iter_with_setup(ComplianceWitness::default, |witness| do_prove(&witness));
    });

    group.finish();
}

/// Precomputed kind table from file: the circuit resolves kind points via table
/// lookup, skipping `hash_to_curve`. The witness uses the `logic_ref` and
/// `label_ref` of the first entry in the loaded table so both consumed and
/// created resources are guaranteed to hit the table.
fn bench_file_table(c: &mut Criterion) {
    let kind_table_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../arm/kind_table.json");
    init_kind_table_from_file(&kind_table_path).expect("Failed to load kind_table.json");

    let entry = &global_kind_table()[0];
    let logic_ref = entry.logic_ref;
    let label_ref = entry.label_ref;

    let mut group = c.benchmark_group("compliance/file_table");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("prove", |b| {
        b.iter_with_setup(
            || make_witness(logic_ref, label_ref),
            |witness| do_prove(&witness),
        );
    });

    group.finish();
}

criterion_group!(benches, bench_empty_table, bench_file_table);
criterion_main!(benches);
