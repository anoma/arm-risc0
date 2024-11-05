defmodule Sha256Test do
  use ExUnit.Case

  test "sha256_single" do
    input = String.to_charlist("test message")
    hash = Risc0.sha256_single(input)

    # Verify hash is 32 bytes (256 bits)
    assert length(hash) == 32
    # Verify deterministic - same input produces same hash
    assert hash == Risc0.sha256_single(input)
  end

  test "sha256_double" do
    input1 = String.to_charlist("first message")
    input2 = String.to_charlist("second message")
    hash = Risc0.sha256_double(input1, input2)

    # Verify hash is 32 bytes
    assert length(hash) == 32
    # Verify deterministic
    assert hash == Risc0.sha256_double(input1, input2)
    # Verify order doesn't matter
    refute hash == Risc0.sha256_double(input2, input1)
  end

  test "sha256_many" do
    inputs = [
      String.to_charlist("first"),
      String.to_charlist("second"),
      String.to_charlist("third")
    ]
    hash = Risc0.sha256_many(inputs)

    # Verify hash is 32 bytes
    assert length(hash) == 32
    # Verify deterministic
    assert hash == Risc0.sha256_many(inputs)
    # Verify order doesn't matter
    reversed = Enum.reverse(inputs)
    refute hash == Risc0.sha256_many(reversed)
  end
end
