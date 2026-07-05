/// Compliance circuit benchmarks.
///
/// Measures wall-clock prove time across four configurations:
///
/// - `empty_table`:            no pre-computed kind points; circuit uses `hash_to_curve`.
/// - `file_table`:             kind points loaded from `kind_table.json`; circuit uses
///                             table lookup, skipping `hash_to_curve`.
/// - `conversion_count`:       fixed 1 resource pair, varying number of conversion
///                             witnesses (0, 1, 2, 4, 8). Tests proving-time scaling
///                             with conversion count.
/// - `conversion_table_size`:  fixed 1 conversion witness, varying conversion table size
///                             (1, 4, 16, 64 entries total). Dummy entries are prepended
///                             so the real conversion is always found last — worst-case
///                             linear scan.
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
use anoma_rm_risc0::compliance::{
    ComplianceWitness, ConversionTableEntry, ConversionWitness, INITIAL_ROOT,
};
use anoma_rm_risc0::constants::{global_kind_table, init_kind_table_from_file};
use anoma_rm_risc0::nullifier_key::NullifierKey;
use anoma_rm_risc0::resource::{ConsumedResourceWitness, Resource};
use compliance_methods::COMPLIANCE_GUEST_ELF;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use risc0_zkvm::{
    default_prover,
    sha::{Impl as ShaImpl, Sha256},
    Digest, ExecutorEnv, ProverOpts,
};
use std::time::Duration;

const RESOURCE_COUNTS: &[usize] = &[1, 2, 4, 8];
const CONVERSION_COUNTS: &[usize] = &[0, 1, 2, 4, 8];
const TABLE_SIZES: &[usize] = &[1, 4, 16, 64];

fn do_prove(witness: &ComplianceWitness) {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();
    default_prover()
        .prove_with_opts(env, COMPLIANCE_GUEST_ELF, &ProverOpts::succinct())
        .unwrap();
}

/// Produces a distinct `Digest` for each `seed` value by hashing the seed byte.
fn seed_digest(seed: u8) -> Digest {
    *ShaImpl::hash_bytes(&[seed])
}

/// Build a compliance witness with `count` consumed/created resources and no conversions.
/// Each consumed resource gets a unique nonce via its index in the last byte.
fn make_witness(logic_ref: Digest, label_ref: Digest, count: usize) -> ComplianceWitness {
    let nf_key = NullifierKey::default();

    let consumed_data: Vec<ConsumedResourceWitness> = (0..count)
        .map(|i| {
            let mut nonce = [0u8; 32];
            nonce[31] = i as u8;
            let resource = Resource {
                logic_ref,
                label_ref,
                quantity: 1,
                value_ref: Digest::default(),
                is_ephemeral: false,
                nonce,
                nk_commitment: nf_key.commit(),
                rand_seed: [0u8; 32],
            };
            ConsumedResourceWitness::from_resource(resource, nf_key.clone())
        })
        .collect();

    let nullifiers: Vec<Digest> = consumed_data
        .iter()
        .map(|w| w.resource.nullifier(&nf_key).unwrap())
        .collect();

    let created_resources: Vec<Resource> = (0..count)
        .map(|i| {
            let nonce = Resource::derive_nonce_from_nullifiers(i as u32, &nullifiers).unwrap();
            Resource {
                logic_ref,
                label_ref,
                quantity: 1,
                value_ref: Digest::default(),
                is_ephemeral: false,
                nonce,
                nk_commitment: nf_key.commit(),
                rand_seed: [0u8; 32],
            }
        })
        .collect();

    ComplianceWitness {
        consumed_data,
        created_resources,
        ephemeral_root: *INITIAL_ROOT,
        rcv: [vec![0u8; 31], vec![1u8]].concat(),
        kind_table: global_kind_table().to_vec(),
        conversions: vec![],
        conversion_table: vec![],
    }
}

/// Build a compliance witness with 1 consumed/created resource pair and `n_conversions`
/// distinct kind-conversion witnesses.
///
/// The conversion table contains `n_table_entries` total entries. Dummy entries occupy
/// the first `n_table_entries - n_conversions` slots so that the real entries are always
/// found at the end of the table — exercising the worst-case O(n) linear scan.
///
/// Each conversion pair uses a distinct `logic_ref` derived from `seed_digest`, so every
/// conversion contributes a new entry to the `accumulate_kind` map rather than collapsing
/// into an existing one.
fn make_conversion_witness(n_conversions: usize, n_table_entries: usize) -> ComplianceWitness {
    let nf_key = NullifierKey::default();

    // One balanced consumed/created pair of the base kind (logic_ref = 0x00 hash).
    let base_logic = Digest::default();
    let base_label = Digest::default();
    let consumed_resource = Resource {
        logic_ref: base_logic,
        label_ref: base_label,
        quantity: 1,
        value_ref: Digest::default(),
        is_ephemeral: false,
        nonce: [0u8; 32],
        nk_commitment: nf_key.commit(),
        rand_seed: [0u8; 32],
    };
    let consumed_data = vec![ConsumedResourceWitness::from_resource(
        consumed_resource,
        nf_key.clone(),
    )];
    let nullifiers: Vec<Digest> = consumed_data
        .iter()
        .map(|w| w.resource.nullifier(&nf_key).unwrap())
        .collect();
    let created_nonce = Resource::derive_nonce_from_nullifiers(0, &nullifiers).unwrap();
    let created_resources = vec![Resource {
        logic_ref: base_logic,
        label_ref: base_label,
        quantity: 1,
        value_ref: Digest::default(),
        is_ephemeral: false,
        nonce: created_nonce,
        nk_commitment: nf_key.commit(),
        rand_seed: [0u8; 32],
    }];

    // Helper: compute the kind EC point for a given logic_ref.
    // nk_commitment is irrelevant to kind() — only logic_ref and label_ref matter.
    let dummy_nk = nf_key.commit();
    let kind_point_for = |logic_ref: Digest| {
        Resource {
            logic_ref,
            label_ref: Digest::default(),
            quantity: 1,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce: [0u8; 32],
            nk_commitment: dummy_nk,
            rand_seed: [0u8; 32],
        }
        .kind()
        .unwrap()
    };

    // Dummy entries prepended (worst-case scan: real entries are found last).
    // Seeds 200..200+2*n_dummy avoid overlapping with the real pair seeds.
    let n_dummy = n_table_entries.saturating_sub(n_conversions);
    let mut conversion_table = Vec::with_capacity(n_table_entries);
    for i in 0..n_dummy {
        let old_logic = seed_digest((200 + 2 * i) as u8);
        let new_logic = seed_digest((201 + 2 * i) as u8);
        let old_pt = kind_point_for(old_logic);
        let new_pt = kind_point_for(new_logic);
        conversion_table.push(ConversionTableEntry::new(
            old_logic,
            Digest::default(),
            new_logic,
            Digest::default(),
            &old_pt,
            &new_pt,
            None,
        ));
    }

    // Real conversion entries (seeds 1, 2, 3, 4, ... so each pair is distinct).
    let mut conversions = Vec::with_capacity(n_conversions);
    for i in 0..n_conversions {
        let old_logic = seed_digest((1 + 2 * i) as u8);
        let new_logic = seed_digest((2 + 2 * i) as u8);
        let old_pt = kind_point_for(old_logic);
        let new_pt = kind_point_for(new_logic);
        conversions.push(ConversionWitness {
            old_logic_ref: old_logic,
            old_label_ref: Digest::default(),
            new_logic_ref: new_logic,
            new_label_ref: Digest::default(),
            quantity: 1,
        });
        conversion_table.push(ConversionTableEntry::new(
            old_logic,
            Digest::default(),
            new_logic,
            Digest::default(),
            &old_pt,
            &new_pt,
            None,
        ));
    }

    ComplianceWitness {
        consumed_data,
        created_resources,
        ephemeral_root: *INITIAL_ROOT,
        rcv: [vec![0u8; 31], vec![1u8]].concat(),
        kind_table: global_kind_table().to_vec(),
        conversions,
        conversion_table,
    }
}

/// Empty kind table: the circuit falls back to `hash_to_curve` for every resource.
fn bench_empty_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance/empty_table");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &count in RESOURCE_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", count), &count, |b, &count| {
            b.iter_with_setup(
                || make_witness(Digest::default(), Digest::default(), count),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

/// Precomputed kind table from file: the circuit resolves kind points via table
/// lookup, skipping `hash_to_curve`. The witness uses the `logic_ref` and
/// `label_ref` of the first entry in the loaded table so all resources hit the table.
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

    for &count in RESOURCE_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", count), &count, |b, &count| {
            b.iter_with_setup(
                || make_witness(logic_ref, label_ref, count),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

/// Varying conversion count: 1 balanced resource pair, 0..8 conversion witnesses.
/// The conversion table has exactly as many entries as there are conversions.
/// Shows how proof time scales with the number of distinct kind conversions per unit.
fn bench_conversion_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance/conversion_count");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &n in CONVERSION_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, &n| {
            b.iter_with_setup(
                || make_conversion_witness(n, n),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

/// Varying conversion table size: 1 conversion witness, table padded to 1..64 entries.
/// Dummy entries precede the real entry (worst-case linear scan).
/// Shows how proof time scales with table size independent of conversion count.
fn bench_conversion_table_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance/conversion_table_size");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &n in TABLE_SIZES {
        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, &n| {
            b.iter_with_setup(
                || make_conversion_witness(1, n),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_empty_table,
    bench_file_table,
    bench_conversion_count,
    bench_conversion_table_size
);
criterion_main!(benches);
