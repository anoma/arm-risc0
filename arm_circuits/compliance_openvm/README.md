# OpenVM Compliance Benchmark

Proves the ARM compliance circuit using [OpenVM](https://github.com/openvm-org/openvm) with accelerated secp256k1 + SHA-256 extensions.

## Setup

Clone OpenVM and checkout the alpha tag:

```bash
git clone https://github.com/openvm-org/openvm.git ~/openvm
cd ~/openvm
git checkout v2.0.0-alpha
```

Copy the compliance guest and test infrastructure into the OpenVM monorepo:

```bash
# Guest program (as an ECC test example)
cp arm_circuits/compliance_openvm/guest/src/compliance.rs ~/openvm/extensions/ecc/tests/programs/src/compliance.rs
cp arm_circuits/compliance_openvm/guest/src/main.rs ~/openvm/extensions/ecc/tests/programs/examples/compliance.rs

# Make compliance module public in the test programs lib
echo 'pub mod compliance;' >> ~/openvm/extensions/ecc/tests/programs/src/lib.rs

# Copy the openvm_init.rs (same as the ec example — secp256k1 moduli)
cp ~/openvm/extensions/ecc/tests/programs/openvm_init_ec_k256.rs ~/openvm/extensions/ecc/tests/programs/openvm_init.rs

# Create the VM config with both ECC and SHA-256 extensions
cat > ~/openvm/extensions/ecc/tests/programs/openvm_compliance.toml << 'EOF'
[app_vm_config.rv32i]
[app_vm_config.rv32m]
[app_vm_config.io]
[app_vm_config.sha256]
[app_vm_config.modular]
supported_moduli = ["115792089237316195423570985008687907853269984665640564039457584007908834671663", "115792089237316195423570985008687907852837564279074904382605163141518161494337"]

[[app_vm_config.ecc.supported_curves]]
struct_name = "Secp256k1Point"
modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
scalar = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
a = "0"
b = "7"
EOF
```

Add deps to the ECC test programs (`~/openvm/extensions/ecc/tests/programs/Cargo.toml`):

```toml
# Add after the openvm-keccak256 line:
openvm-sha2 = { path = "../../../../guest-libs/sha2" }
```

Add a `[[example]]` entry to the same file:

```toml
[[example]]
name = "compliance"
required-features = ["k256"]
```

Add deps to the ECC integration tests (`~/openvm/extensions/ecc/tests/Cargo.toml`):

```toml
# Add to [dependencies]:
openvm-sha256-transpiler = { workspace = true }
sha2 = "0.10"
hex = "0.4"
```

Then add the test function to `~/openvm/extensions/ecc/tests/src/lib.rs` inside `mod tests { }` — see `guest/src/compliance.rs` header comment for the full test function.

## Run

```bash
cd ~/openvm
OPENVM_FAST_TEST=1 OPENVM_SKIP_DEBUG=1 cargo test --profile fast \
  -p openvm-ecc-integration-tests -- test_compliance --nocapture
```

First run compiles the guest for RISC-V and generates proving keys (~30s). The proof generation itself is the remaining time.

## What It Proves

Same compliance circuit as the Jolt and risc0 benchmarks:

- Resource commitment integrity (SHA-256, accelerated)
- Nullifier derivation (SHA-256, accelerated)
- Merkle path inclusion (SHA-256 chain, depth 10)
- Delta commitment (secp256k1 EC ops, accelerated via modular arithmetic extension)
- Nonce binding (created nonce == consumed nullifier)

Public output: `SHA-256(ComplianceInstance)` revealed via `reveal_bytes32`.

## Results (CPU, no GPU)

| Benchmark | Prove | Notes |
|-----------|-------|-------|
| **OpenVM compliance** | **46s** | STARK (Plonky3), accelerated secp256k1 + SHA-256 |
| Jolt compliance | 54s | Spartan+Dory, secp256k1 + SHA-256 inlines |
| risc0 compliance | 986s | STARK succinct, SHA-256 precompile, software EC |

OpenVM is the fastest and has a full on-chain verification pipeline (STARK → Halo2 → Solidity verifier), though EVM proof generation was not benchmarked here.

## Caveats

- **hash-to-curve**: `kind()` uses hash-to-scalar * G instead of RFC 9380 hash-to-curve. Same EC operation count but discrete log of kind points is known. Not suitable for production.
- **Runs inside OpenVM monorepo**: The benchmark is wired into the ECC integration test suite because OpenVM examples are not standalone — they require the monorepo's workspace dependency resolution.
- **v2.0.0-alpha tag is broken for external consumers**: The tag's git dependencies have version conflicts when used outside the monorepo. Must build from within the cloned repo.
