#!/usr/bin/env bash
# Rebuilds all guest ELFs reproducibly via cargo risczero build (Docker),
# copies them to the checked-in paths, and patches the image IDs in constants.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

extract_image_id() {
    # Parses "ImageID: <hex> - <path>" from cargo risczero build stdout
    grep 'ImageID:' | sed 's/ImageID: \([0-9a-f]*\).*/\1/'
}

echo "==> Building compliance guest"
COMPLIANCE_OUT=$(cargo risczero build \
    --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml 2>&1 | tee /dev/stderr)
COMPLIANCE_ID=$(echo "$COMPLIANCE_OUT" | extract_image_id)
cp arm_circuits/compliance/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/compliance-guest.bin \
    arm/elfs/compliance-guest.bin

echo "==> Building trivial logic (padding) guest"
TRIVIAL_OUT=$(cargo risczero build \
    --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml 2>&1 | tee /dev/stderr)
TRIVIAL_ID=$(echo "$TRIVIAL_OUT" | extract_image_id)
cp arm_circuits/trivial_logic/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/trivial-logic-guest.bin \
    arm/elfs/trivial-logic-guest.bin

echo "==> Building logic test guest"
LOGIC_TEST_OUT=$(cargo risczero build \
    --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml 2>&1 | tee /dev/stderr)
LOGIC_TEST_ID=$(echo "$LOGIC_TEST_OUT" | extract_image_id)
cp arm_circuits/logic_test/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/logic-test-guest.bin \
    arm_tests/arm_test_app/elf/logic-test-guest.bin

echo "==> Building batch aggregation guest (default)"
AGG_OUT=$(cargo risczero build \
    --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml 2>&1 | tee /dev/stderr)
AGG_ID=$(echo "$AGG_OUT" | extract_image_id)
cp arm_circuits/batch_aggregation/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/batch-aggregation-guest.bin \
    arm/elfs/batch-aggregation-guest.bin

echo "==> Building batch aggregation guest (EVM ABI-encoded)"
AGG_EVM_OUT=$(cargo risczero build \
    --manifest-path arm_circuits/batch_aggregation/methods/guest/Cargo.toml \
    --features abi_encoding 2>&1 | tee /dev/stderr)
AGG_EVM_ID=$(echo "$AGG_EVM_OUT" | extract_image_id)
# The emitted artifact is still named batch-aggregation-guest.bin regardless of features
cp arm_circuits/batch_aggregation/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/batch-aggregation-guest.bin \
    arm/elfs/batch-aggregation-evm-guest.bin

echo ""
echo "==> Patching arm_core/src/constants.rs and test constants"
# Use Python for multi-line-safe in-place substitution of each digest:
# the VK consts live in arm_core as Digest::new(words) with the canonical
# hex in the doc comment and pinned in a test, so each update replaces the
# hex everywhere in the file and regenerates the words array.
python3 - <<PYEOF
import re, pathlib

def words_for(hexstr):
    b = bytes.fromhex(hexstr)
    ws = [int.from_bytes(b[i:i+4], 'little') for i in range(0, 32, 4)]
    return ', '.join(f'0x{w:08x}' for w in ws)

def patch_const(name, new_hex):
    path = pathlib.Path("arm_core/src/constants.rs")
    text = path.read_text()
    m = re.search(
        r'([0-9a-f]{64})(\.\s*\n\s*pub const ' + name + r': Digest = Digest::new\(\[)([^\]]*)(\]\);)',
        text,
    )
    if not m:
        raise SystemExit(f"  ERROR: const {name} not found in {path}")
    old_hex = m.group(1)
    if old_hex == new_hex:
        print(f"  {name}: unchanged ({new_hex[:16]}...)")
        return
    text = text.replace(old_hex, new_hex)
    text = text.replace(m.group(3), "\n    " + words_for(new_hex) + ",\n", 1)
    path.write_text(text)
    print(f"  {name}: {old_hex[:16]}... -> {new_hex[:16]}...")

patch_const("COMPLIANCE_VK", "$COMPLIANCE_ID")
patch_const("PADDING_LOGIC_VK", "$TRIVIAL_ID")
patch_const("BATCH_AGGREGATION_VK", "$AGG_ID")
patch_const("BATCH_AGGREGATION_EVM_VK", "$AGG_EVM_ID")

def extract_vks(text):
    return dict(re.findall(
        r'static ref (\w+): Digest\s*=\s*\n?\s*Digest::from_hex\("([0-9a-f]+)"\)',
        text
    ))

def patch_hex(path, old_hex, new_hex):
    text = pathlib.Path(path).read_text()
    if old_hex not in text:
        print(f"  WARNING: {old_hex[:16]}... not found in {path}")
        return
    pathlib.Path(path).write_text(text.replace(old_hex, new_hex, 1))
    print(f"  {path}: {old_hex[:16]}... -> {new_hex[:16]}...")

lib = pathlib.Path("arm_tests/arm_test_app/src/lib.rs").read_text()
vks2 = extract_vks(lib)
patch_hex("arm_tests/arm_test_app/src/lib.rs", vks2["TEST_LOGIC_VK"], "$LOGIC_TEST_ID")
PYEOF

echo ""
echo "==> Image IDs"
echo "  COMPLIANCE_VK:          $COMPLIANCE_ID"
echo "  PADDING_LOGIC_VK:       $TRIVIAL_ID"
echo "  TEST_LOGIC_VK:          $LOGIC_TEST_ID"
echo "  BATCH_AGGREGATION_VK:   $AGG_ID"
echo "  BATCH_AGGREGATION_EVM_VK: $AGG_EVM_ID"
echo ""
echo "Done. Run 'cargo check' to verify."
