# Anoma Resource Machine Circuits

Demonstration circuits for the Anoma Resource Machine (ARM) built on RISC0 zkVM. These crates generate guest binaries (ELFs) and image IDs used by the ARM proving system and applications.

## Overview

This workspace includes circuit crates and their corresponding RISC0 method builds:

- [arm_circuits/compliance](arm_circuits/compliance): Basic compliance checking circuit and method generation
- [arm_circuits/trivial_logic](arm_circuits/trivial_logic): Minimal logic circuit example (also used for padding resources)
- [arm_circuits/logic_test](arm_circuits/logic_test): Test logic circuit used by the test app and SDK bindings
- [arm_circuits/batch_aggregation](arm_circuits/batch_aggregation): Single-run batch aggregation methods

## Prerequisites

- Rust toolchain (Edition 2021)
- RISC0 toolchain and `cargo risczero` subcommand installed

## Reproducible Method Builds (ELF & ImageID)

Run from the repository root to generate guest ELFs and image IDs reproducibly:

```bash
cd ..
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml

# EVM ABI-encoded output variant (the emitted artifact is still named batch-aggregation-guest.bin)
cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml --features abi_encoding
# Copy/rename the emitted artifact to arm/elfs/batch-aggregation-evm-guest.bin before updating the VK.
cp arm/elfs/batch-aggregation-guest.bin arm/elfs/batch-aggregation-evm-guest.bin
```

After copying, update `BATCH_AGGREGATION_EVM_VK` in `arm/src/constants.rs` with the image ID printed by the command above.

## Regenerating After Changes

If you modify guest code under any `methods/guest` folder, rebuild methods:

```bash
cargo clean
cd ..
cargo risczero build --manifest-path arm_circuits/<circuit>/methods/guest/Cargo.toml
```

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE).