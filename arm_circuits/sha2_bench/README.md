# sha2_bench

Benchmarks SHA-256 hashing inside a RISC Zero zkVM circuit. For each of 10, 100, 1000, and 10000 hashes, it reports proving time, verification time, and cycle counts.

## Running

From `arm_circuits/`:

```sh
cargo run -p sha2-bench --features prove
```

## Benchmarks

| Hashes | User / Total Cycles | Proving | Verification |
|---|---|---|---|
| 10 | 12,007 / 65,536 | 13.26s | 18.55ms |
| 100 | 57,727 / 131,072 | 18.51s | 18.44ms |
| 1,000 | 514,927 / 1,048,576 | 86.11s | 18.41ms |
| 10,000 | 5,086,927 / 6,291,456 | 540.92s | 18.53ms |
