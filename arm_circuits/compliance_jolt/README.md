# Jolt Compliance Benchmark

Proves the ARM compliance circuit using [Jolt](https://github.com/a16z/jolt) zkVM with secp256k1 + SHA-256 inline optimizations.

## Setup

Requires OpenSSL dev headers (`libssl-dev` on Ubuntu).

Clone Jolt `main` branch:

```bash
git clone https://github.com/a16z/jolt.git /tmp/jolt-workspace
```

Copy compliance project into the Jolt workspace:

```bash
mkdir -p /tmp/jolt-workspace/examples/compliance/src
cp -r arm_circuits/compliance_jolt/guest /tmp/jolt-workspace/examples/compliance/guest
cp arm_circuits/compliance_jolt/src/main.rs /tmp/jolt-workspace/examples/compliance/src/main.rs
cp arm_circuits/compliance_jolt/host-Cargo.toml /tmp/jolt-workspace/examples/compliance/Cargo.toml
```

Add to workspace members in `/tmp/jolt-workspace/Cargo.toml`, after the existing examples:

```toml
    "examples/compliance",
    "examples/compliance/guest",
```

Install the Jolt CLI (required for guest compilation):

```bash
cd /tmp/jolt-workspace
cargo install --path .
```

## Run

```bash
cd /tmp/jolt-workspace
cargo run -p compliance-jolt-host --release
```

First run compiles the guest for RISC-V and generates the Dory SRS (~5 min). Subsequent runs reuse cached artifacts.

## What It Proves

The compliance circuit verifies a resource state transition per the [Anoma RM spec](https://specs.anoma.net/latest/arch/system/state/resource_machine/data_structures/compliance_unit/compliance_proof.html):

- Resource commitment integrity (SHA-256)
- Nullifier derivation (SHA-256)
- Merkle path inclusion (SHA-256 chain, depth 10)
- Delta commitment (secp256k1 scalar multiplication + point arithmetic, GLV-accelerated)
- Nonce binding (created nonce == consumed nullifier)

Public output: `SHA-256(ComplianceInstance)` — a binding commitment to the full instance (nullifier, logic refs, tree root, commitment, delta coordinates).

## Results (CPU, no GPU)

| Benchmark | Prove | Verify |
|-----------|-------|--------|
| Jolt fib(50) v0.2.1 | 6s | - |
| risc0 fib(50) v3.0 | 13.6s | 13ms |
| **Jolt compliance (inlines)** | **63s** | **248ms** |
| risc0 compliance (STARK succinct) | 986s | 19ms |

Jolt with secp256k1 + SHA-256 inlines is ~16x faster than risc0 for the compliance proof.

## Caveats

- **hash-to-curve**: `kind()` uses hash-to-scalar * G instead of RFC 9380 hash-to-curve. Exercises the same EC operations but the discrete log of kind points is known. Not suitable for production.
- **No on-chain verification**: Jolt produces a Spartan+Dory proof, not Groth16. No Groth16 wrapping pipeline exists yet.
- **Requires Jolt `main` branch**: secp256k1 inlines are not in any tagged release as of v0.3.0-alpha.
- **Hash endianness**: SHA-256 word-to-byte ordering may differ from the risc0 implementation. Proof outputs are internally consistent but won't match risc0 values for the same witness.
