# ecdsa_bench

Benchmarks ECDSA-secp256k1 signature verification inside a RISC Zero zkVM circuit. For 1 and 10 verifications, it reports proving time, verification time, and cycle counts.

## Running

From `arm_circuits/`:

```sh
cargo run -p ecdsa-bench --features prove
```

## Benchmarks

| Verifications | User / Total Cycles | Proving | Verification |
|---|---|---|---|
| 1 | 340,472 / 524,288 | 45.13s | 19.20ms |
| 10 | 3,067,240 / 3,407,872 | 311.68s | 19.39 |
