# Anoma Risc0 Resource Machine

This is a shielded resource machine implementation based on Risc0-zkvm.

## Reproducibly generate proving and verifying keys (ELF and ImageID)

You may generate different ELFs and ImageIDs on different machines and environments. To reproduce the same output and publicly verify that the ELF and ImageID correspond to the specific circuit source code, use the following tool and command.

For example, build the compliance circuit in RM:

```bash
cargo risczero build --manifest-path examples/compliance_circuit/methods/guest/Cargo.toml
```

will reproduce the output to:

```bash
View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/zbrzf1brqyb5evydjxs9h3gvl

ELFs ready at:
ImageID: 292f133f48a8a74efaec4079554f9b33e3ef1ffb263273f0e15850dfc3799895 - 
arm-risc0/examples/compliance_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/compliance-guest.bin
```

Note: The `unstable` feature of `risc0-zkvm` currently causes issues in circuits. This can be temporarily fixed by manually updating the tool. The problem will be fully resolved in the next release of RISC Zero.
```bash
cargo install --force --git https://github.com/risc0/risc0 --tag v2.1.0 -Fexperimental cargo-risczero
```