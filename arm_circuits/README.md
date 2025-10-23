## Generate proving and verifying keys (ELF and ImageID) reproducibly for releasing
```bash
cd ..
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/counter/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/kudo_main/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/simple_kudo_denomination/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/simple_kudo_receive/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/simple_transfer/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/sequential_aggregation/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml
```

## Generate and print proving and verifying keys (ELF and ImageID) locally for debugging.
```bash
// It covers the previous ELF files, prints their IDs. You need to manually update ids in apps for testing.
cargo test -- --nocapture print_compliance_elf_id
cargo test -- --nocapture print_counter_elf_id
cargo test -- --nocapture print_kudo_main_elf_id
cargo test -- --nocapture print_simple_kudo_denomination_elf_id
cargo test -- --nocapture print_simple_kudo_receive_elf_id
cargo test -- --nocapture print_trivial_logic_elf_id
```