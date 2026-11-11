# Anoma Resource Machine Circuits

Demonstration circuits for the Anoma Resource Machine (ARM) built on RISC0 zkVM. These crates generate guest binaries (ELFs) and image IDs used by the ARM proving system and applications.

## Overview

This workspace includes circuit crates and their corresponding RISC0 method builds:

- [compliance](./compliance): Basic compliance checking circuit and method generation
- [trivial_logic](./trivial_logic): Minimal logic circuit example (also used for padding resources)
- [logic_test](./logic_test): Test logic circuit used by the test app and SDK bindings
- [batch_aggregation](./batch_aggregation): Single-run batch aggregation methods

## Prerequisites

- Host Rust 1.89, as pinned in `../rust-toolchain.toml`
- RISC Zero `cargo-risczero` and `r0vm` 3.1.0
- Docker running for reproducible guest builds

The Docker guest builder uses the separate RISC Zero Rust 1.97.0 toolchain.

## Current release artifacts

`2.0.0-rc.9` ships these RISC Zero 3.1.0 guest image IDs, built with
`risczero/risc0-guest-builder:r0.1.97.0`:

| Constant | Image ID |
| --- | --- |
| `COMPLIANCE_VK` | `23e01dda73611df43ef58e427133f8fdded73a26e0b8b950a616beb2318cdb76` |
| `PADDING_LOGIC_VK` | `b6cb7fcdf12a0413da86c4edea128bec945f82071f1c268bc16ef89ba931cca5` |
| `TEST_LOGIC_VK` | `2e1475f0e295b74ee1b40b916c8888ab01c90db8f02e990e376e660fb3c1b0ae` |
| `BATCH_AGGREGATION_VK` | `0c805c99e67b653672463c13a1c8c7b14241cf49f7f9a56ba9a829683fe13948` |
| `BATCH_AGGREGATION_EVM_VK` | `a76ad2f5b2989aceb0320d604c2425be30fac04e855d6ce1dec8f731601ab3d4` |

The [starter kind tree](../arm/data/kind_tree.json) contains the padding
and test logic entries under the zero label. Its root is
`44b55c0dcd39680f5dd98c5a15e62661e04cead552d4d76c6e37d3e3abec8b59`.

## Reproducible Method Builds (ELF & ImageID)

### Automated (recommended)

Run the update script from the repository root. It builds all guests, copies the
ELFs to their checked-in paths, and patches the image IDs in
`arm_core/src/constants.rs` (the `*_VK` consts, which `arm/src/constants.rs`
re-exports) and `arm_tests/arm_test_app/src/lib.rs` in one step:

```bash
./scripts/update_elfs.sh
```

Requires Docker (used by `cargo risczero build` for reproducible builds) and
`cargo risczero` installed. When the padding or test logic ID changes, also
follow the [starter kind-tree update steps](#updating-the-starter-kind-tree).

### Manual

Run from the repository root to generate guest ELFs and image IDs reproducibly:

```bash
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml

# EVM ABI-encoded output variant (the emitted artifact is still named batch-aggregation-guest.bin)
cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml --features abi_encoding
# Copy the artifact to its checked-in path.
cp arm_circuits/batch_aggregation/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/batch-aggregation-guest.bin \
    arm/elfs/batch-aggregation-evm-guest.bin
```

After each build, copy the ELF from
`<circuit>/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/<name>.bin`
to the appropriate path under `arm/elfs/` or `arm_tests/arm_test_app/elf/`,
then update the corresponding `*_VK` constant in `arm_core/src/constants.rs`
with the printed image ID. Each const is pinned against its canonical hex in a
test there, so the hex in the doc comment and in `vk_consts_match_hex` has to
move with it — `./scripts/update_elfs.sh` does both.

## Regenerating After Changes

If you modify guest code under any `methods/guest` folder, rerun
`./scripts/update_elfs.sh` (or the individual `cargo risczero build` command
for the affected circuit).

### Updating the starter kind tree

The ELF update script patches the image-ID constants. The starter tree and
the test-logic ID in the kind-base printing utility must also follow those IDs:

1. Copy the new `TEST_LOGIC_VK` from `arm_tests/arm_test_app/src/lib.rs` into
   `print_kind_bases_for_vks` in `arm/src/constants.rs`.
2. From the repository root, print the new padding and test kind bases:

   ```bash
   cargo test -p anoma-rm-risc0 --lib constants::tests::print_kind_bases_for_vks -- --ignored --exact --nocapture
   ```

3. Update each entry in `arm/data/kind_tree.json` with its new `logic_ref`
   and printed `kind_base`. Keep `label_ref` equal to the zero digest.
4. Print the updated root in an isolated test process:

   ```bash
   cargo test -p anoma-rm-risc0 --lib constants::tests::print_kind_tree_root -- --ignored --exact --nocapture
   ```

5. Refresh the release IDs and root in these READMEs. Verifiers using this
   starter tree must use the updated expected root.

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE).
