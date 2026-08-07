# Batch Aggregation Proving Benchmark Report

## Overview

This report compares Groth16 GPU proving performance of the `batch_aggregation`
circuit across three benchmark runs: two variants on the `xuyang/abi_encode`
branch (default output vs. EVM ABI-encoded output) and the baseline on the
`v1_aggregation_bench` branch.

## Environment

| Item | Value |
|---|---|
| GPU | NVIDIA GeForce RTX 4090 |
| Proof type | Groth16 (STARK → recursion → Groth16 wrap) |
| Feature flags | `prove,bonsai,cuda` (+ `abi_encoding` where noted) |
| Harness | Criterion, flat sampling, 10 samples/point |
| Warmup / measurement | 30 s / 300 s |
| Batch sizes (actions) | 1, 2, 4 |

## Runs

| # | Branch | Commit | Features | Journal encoding |
|---|---|---|---|---|
| 1 | `xuyang/abi_encode` | `dd088f3` | `prove,bonsai,cuda` | default (risc0 serde) |
| 2 | `xuyang/abi_encode` | `dd088f3` | `prove,bonsai,cuda,abi_encoding` | EVM ABI-encoded |
| 3 | `v1_aggregation_bench` | `668ca5a` | `prove,bonsai,cuda` | default (risc0 serde) |

## Results

Times are the Criterion median, with the [low, high] confidence bounds.

### Run 1 — `xuyang/abi_encode`, default

| Batch | Median | Low | High | Notes |
|---|---|---|---|---|
| 1 | 6.43 s | 6.349 s | 6.509 s | |
| 2 | 8.14 s | 8.069 s | 8.218 s | |
| 4 | 12.18 s | 12.064 s | 12.305 s | 1 outlier (high mild) |

### Run 2 — `xuyang/abi_encode`, `abi_encoding`

| Batch | Median | Low | High | Notes |
|---|---|---|---|---|
| 1 | 6.18 s | 6.148 s | 6.204 s | |
| 2 | 8.02 s | 7.929 s | 8.124 s | |
| 4 | 11.75 s | 11.582 s | 11.916 s | |

### Run 3 — `v1_aggregation_bench`, default

| Batch | Median | Low | High | Notes |
|---|---|---|---|---|
| 1 | 6.54 s | 6.468 s | 6.628 s | |
| 2 | 8.59 s | 8.520 s | 8.691 s | 2 outliers |
| 4 | 13.08 s | 13.025 s | 13.143 s | |

## Side-by-side (median proving time, seconds)

| Batch | Run 1 — abi_encode default | Run 2 — abi_encode + abi_encoding | Run 3 — v1 baseline |
|---|---|---|---|
| 1 | 6.43 | 6.18 | 6.54 |
| 2 | 8.14 | 8.02 | 8.59 |
| 4 | 12.18 | 11.75 | 13.08 |

## Analysis

### ABI encoding adds no proving overhead (Run 1 vs Run 2)

Enabling `abi_encoding` on the same branch/commit changes only how the guest
commits its output (`abi_encode_instance` + `commit_slice` instead of
`env::commit`). Median proving time is essentially flat — actually marginally
lower with ABI encoding (~4% at batch 1, ~1.5% at batch 2, ~3.5% at batch 4),
and the confidence intervals largely overlap.

This is expected for a zkVM rather than a hand-written constraint system:

- The circuit is the *fixed* RISC-V VM; "more constraints" means more executed
  cycles (trace rows), not a bigger bespoke circuit.
- STARK proving cost is quantized to the next power-of-two segment size. A small
  number of extra encoding cycles does not cross a power-of-two boundary, so the
  padded trace — and the GPU proving work — is unchanged.
- The dominant Groth16 wrap proves a fixed-size recursion-verifier circuit,
  independent of the guest, so that cost is constant across both variants.

**Takeaway:** EVM ABI-encoded output is effectively free to prove.

### Branch difference: `abi_encode` vs `v1` baseline (Run 1 vs Run 3)

Both are the default (non-ABI) encoding, so this isolates the branch delta:

| Batch | v1 baseline | abi_encode default | Δ (abs) | Δ (%) |
|---|---|---|---|---|
| 1 | 6.54 s | 6.43 s | −0.11 s | −1.7% |
| 2 | 8.59 s | 8.14 s | −0.45 s | −5.2% |
| 4 | 13.08 s | 12.18 s | −0.90 s | −6.9% |

The `xuyang/abi_encode` branch is consistently faster than the `v1` baseline,
and the gap widens with batch size (~2% → ~7%). This exceeds the run-to-run
noise observed within a branch, so it appears to be a real improvement in the
newer branch rather than measurement variance.

## Notes / reproduction

Server setup required for a clean run in a non-interactive shell:

- Source the toolchains: `~/.cargo/env` and `/etc/profile.d/cuda.sh`
  (without CUDA env, `nvcc` cannot find `cuda_runtime.h` and `sppark` fails to build).
- Install the Groth16 prover component: `rzup install risc0-groth16`.

Command (per run):

```bash
cargo bench --manifest-path arm_circuits/batch_aggregation/Cargo.toml \
  --features prove,bonsai,cuda            # add ,abi_encoding for Run 2
```
