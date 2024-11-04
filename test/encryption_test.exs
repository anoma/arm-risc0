defmodule EncryptionTest do
  use ExUnit.Case

  @tag timeout: :infinity
  test "encryption_and_decryption" do
    # Generate test data
    message = String.to_charlist("test message")
    {sk_bytes, pk_bytes} = Risc0.generate_keypair()
    nonce = Risc0.random_32()

    # Encrypt the data
    encrypted = Risc0.encrypt(message, pk_bytes, sk_bytes, nonce)


    # Decrypt the data
    decrypted = Risc0.decrypt(encrypted, pk_bytes, sk_bytes, nonce);

    # Verify the decrypted message matches the original
    assert message == decrypted
  end

end
