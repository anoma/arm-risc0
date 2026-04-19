# Compliance Circuit

This crate contains the RISC Zero compliance circuit and its local benchmark.
Succinct STARK proofs are generated in the benchmark by default.

## Run

From this crate directory:

```bash
cargo run --release
```

## Benchmark

Run the local proving benchmark with:

```bash
cargo bench --features prove --bench prove
```

Run the CUDA prover benchmark with:

```bash
cargo bench --features prove,cuda --bench prove
```

For faster iteration without real proof generation:

```bash
RISC0_DEV_MODE=1 cargo bench --features prove --bench prove
```

The benchmark measures two cases:

- `compliance/empty_table/prove`: no precomputed kind table, so the circuit falls back to `hash_to_curve`.
- `compliance/file_table/prove`: loads `kind_table.json` and resolves kind points via table lookup.

## Current Results

```text
compliance/empty_table/prove
                        time:   [1.9714 s 1.9749 s 1.9786 s]
compliance/file_table/prove
                        time:   [767.95 ms 769.00 ms 770.01 ms]
```
