# Compliance Circuit

This crate contains the RISC Zero compliance circuit and its local benchmark.
Succinct STARK proofs are generated in the benchmark by default.

## Benchmark

Run the local proving benchmark with:

```bash
cargo bench --features prove --bench compliance
```

Run the CUDA prover benchmark with:

```bash
cargo bench --features prove,cuda --bench compliance
```

For faster iteration without real proof generation:

```bash
RISC0_DEV_MODE=1 cargo bench --features prove -p compliance
```

The benchmark measures two cases:

- `compliance/empty_table/prove`: no precomputed kind table, so the circuit falls back to `hash_to_curve`.
- `compliance/file_table/prove`: loads `kind_table.json` and resolves kind points via table lookup.

## Current Results

```text
compliance/empty_table/prove
                        time:   [2.7347 s 2.7424 s 2.7538 s]
compliance/file_table/prove
                        time:   [1.0015 s 1.0039 s 1.0067 s]
```
