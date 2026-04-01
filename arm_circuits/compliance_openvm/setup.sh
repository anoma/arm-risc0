#!/bin/bash
# Setup script for OpenVM compliance benchmark
# Run from the arm-risc0 repo root

set -e

OPENVM_DIR=${OPENVM_DIR:-~/openvm}

if [ ! -d "$OPENVM_DIR" ]; then
    echo "Cloning OpenVM..."
    git clone https://github.com/openvm-org/openvm.git "$OPENVM_DIR"
    cd "$OPENVM_DIR" && git checkout v2.0.0-alpha
fi

echo "Copying guest program..."
cp arm_circuits/compliance_openvm/guest/src/compliance.rs "$OPENVM_DIR/extensions/ecc/tests/programs/src/compliance.rs"
cp arm_circuits/compliance_openvm/guest/src/hash_to_curve.rs "$OPENVM_DIR/extensions/ecc/tests/programs/src/hash_to_curve.rs"
cp arm_circuits/compliance_openvm/guest/src/main.rs "$OPENVM_DIR/extensions/ecc/tests/programs/examples/compliance.rs"

echo "Configuring workspace..."
# Add modules (idempotent)
grep -q "pub mod compliance;" "$OPENVM_DIR/extensions/ecc/tests/programs/src/lib.rs" || \
    echo 'pub mod compliance;' >> "$OPENVM_DIR/extensions/ecc/tests/programs/src/lib.rs"
grep -q "pub mod hash_to_curve;" "$OPENVM_DIR/extensions/ecc/tests/programs/src/lib.rs" || \
    echo 'pub mod hash_to_curve;' >> "$OPENVM_DIR/extensions/ecc/tests/programs/src/lib.rs"

# Copy init file
cp "$OPENVM_DIR/extensions/ecc/tests/programs/openvm_init_ec_k256.rs" \
   "$OPENVM_DIR/extensions/ecc/tests/programs/openvm_init.rs"

# VM config with ECC + SHA256
cat > "$OPENVM_DIR/extensions/ecc/tests/programs/openvm_compliance.toml" << 'EOF'
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

# Add deps to test programs
grep -q "openvm-sha2" "$OPENVM_DIR/extensions/ecc/tests/programs/Cargo.toml" || \
    sed -i '/openvm-keccak256/a openvm-sha2 = { path = "../../../../guest-libs/sha2" }' \
    "$OPENVM_DIR/extensions/ecc/tests/programs/Cargo.toml"

grep -q 'name = "compliance"' "$OPENVM_DIR/extensions/ecc/tests/programs/Cargo.toml" || \
    cat >> "$OPENVM_DIR/extensions/ecc/tests/programs/Cargo.toml" << 'EOF'

[[example]]
name = "compliance"
required-features = ["k256"]
EOF

# Add deps to test crate
grep -q "openvm-sha256-transpiler" "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml" || \
    sed -i '/openvm-ecc-transpiler/a openvm-sha256-transpiler = { workspace = true }' \
    "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml"
grep -q 'sha2.workspace' "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml" || \
    sed -i '/openvm-sha256-transpiler/a sha2.workspace = true' "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml"
grep -q 'hex.workspace' "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml" || \
    sed -i '/sha2.workspace/a hex.workspace = true' "$OPENVM_DIR/extensions/ecc/tests/Cargo.toml"

# Apply test function patch
cp arm_circuits/compliance_openvm/test_patch.rs /tmp/test_patch.rs
if ! grep -q "test_compliance" "$OPENVM_DIR/extensions/ecc/tests/src/lib.rs"; then
    # Insert before the last closing brace of mod tests
    LAST_BRACE=$(grep -n "^}" "$OPENVM_DIR/extensions/ecc/tests/src/lib.rs" | tail -1 | cut -d: -f1)
    head -n $((LAST_BRACE - 1)) "$OPENVM_DIR/extensions/ecc/tests/src/lib.rs" > /tmp/ecc_patched.rs
    cat /tmp/test_patch.rs >> /tmp/ecc_patched.rs
    echo "}" >> /tmp/ecc_patched.rs
    cp /tmp/ecc_patched.rs "$OPENVM_DIR/extensions/ecc/tests/src/lib.rs"
fi

echo ""
echo "Setup complete. To run:"
echo "  cd $OPENVM_DIR"
echo "  OPENVM_FAST_TEST=1 OPENVM_SKIP_DEBUG=1 cargo test --profile fast \\"
echo "    -p openvm-ecc-integration-tests -- test_compliance --nocapture"
echo ""
echo "For GPU (CUDA):"
echo "  OPENVM_FAST_TEST=1 OPENVM_SKIP_DEBUG=1 cargo test --profile fast \\"
echo "    -p openvm-ecc-integration-tests --features cuda -- test_compliance --nocapture"
