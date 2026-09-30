# Compliance benchmark results

- **Hardware:** 2x NVIDIA RTX 4090 (24 GB), driver 575.51.03
- **Software:** CUDA 12.9, risc0 3.0.3
- **Branch:** `xuyang/bench_kindtable` @ `0630804`
- **Command:** `cargo bench --features cuda,prove --bench prove` (in `arm_circuits/compliance`)
- **Metric:** criterion median

## empty_table

| Resources | Time |
|---|---|
| 1 | 2.69 s |
| 2 | 3.98 s |
| 4 | 8.05 s |
| 8 | 14.72 s |

## file_table

| Resources | Time |
|---|---|
| 1 | 1.03 s |
| 2 | 1.05 s |
| 4 | 1.51 s |
| 8 | 1.63 s |

## table_size (2 resources)

| Kind-table entries | Time |
|---|---|
| 8 | 1.08 s |
| 16 | 1.54 s |
| 32 | 1.62 s |
| 64 | 2.88 s |
| 128 | 4.53 s |
| 256 | 7.28 s |
| 512 | 14.61 s |
| 1024 | 27.79 s |
| 2048 | 54.89 s |
