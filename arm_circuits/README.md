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

`2.0.0` ships these RISC Zero 3.1.0 guest image IDs, built with
`risczero/risc0-guest-builder:r0.1.97.0`:

| Constant | Image ID |
| --- | --- |
| `COMPLIANCE_VK` | `5f337810d11c37f60cde3e52a0b0bc3fc4516fa3daf94c7f24a359efefe86cc8` |
| `PADDING_LOGIC_VK` | `f89e46714963f36128f3954890e30e6c85212c3a33c57714664d85741e7cc78e` |
| `TEST_LOGIC_VK` | `bd60d8909e2ce2ce9fc352a64e2cc7656be54a3f97febf181c91672e3876d3f0` |
| `BATCH_AGGREGATION_VK` | `2c6cb11fa4c84623245fe83833b2762128ea90986d137a10bf648e56d5b1d74a` |
| `BATCH_AGGREGATION_EVM_VK` | `40043e08c0f46c84453d0c7980fd53d6adba87522e5fac80b481e8c72df64da1` |

The [starter kind tree](../arm/data/kind_tree.json) contains the padding
and test logic entries under the zero label. Its root is
`c5f431396892968610edacbd594780bd3ec3e703ad3ac98408a28b3960974efd`.

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
