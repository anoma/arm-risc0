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

### Automated (recommended)

Run the update script from the repository root. It builds all guests, copies the
ELFs to their checked-in paths, and patches the image IDs in
`arm/src/constants.rs` and `arm_tests/arm_test_app/src/lib.rs` in one step:

```bash
./scripts/update_elfs.sh
```

Requires Docker (used by `cargo risczero build` for reproducible builds) and
`cargo risczero` installed.

### Manual

Run from the repository root to generate guest ELFs and image IDs reproducibly:

```bash
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml

# EVM ABI-encoded output variant (the emitted artifact is still named batch-aggregation-guest.bin)
cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml --features abi_encoding
# Copy/rename the emitted artifact to arm/elfs/batch-aggregation-evm-guest.bin before updating the VK.
cp arm/elfs/batch-aggregation-guest.bin arm/elfs/batch-aggregation-evm-guest.bin
```

After each build, copy the ELF from
`<circuit>/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/<name>.bin`
to the appropriate path under `arm/elfs/` or `arm_tests/arm_test_app/elf/`,
then update the corresponding `*_VK` constant with the printed image ID.

## Regenerating After Changes

If you modify guest code under any `methods/guest` folder, rerun
`./scripts/update_elfs.sh` (or the individual `cargo risczero build` command
for the affected circuit).

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE).