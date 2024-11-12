defmodule Risc0 do
  @moduledoc """
  Interface module for RISC Zero zero-knowledge proof system and encryption functionality.
  Provides functions for proving, verifying, resource generation, and encryption operations.
  """

  @doc """
  Generates a zero-knowledge proof for the given environment and ELF binary.

  ## Parameters
    - env_bytes: The environment data as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - list(byte()) | {:error, term()}: The proof receipt as bytes or an error
  """
  @spec prove(list(byte()), list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate prove(env_bytes, elf),
    to: Risc0.AarmRustler,
    as: :prove

  @doc """
  Verifies a zero-knowledge proof receipt against an ELF binary.

  ## Parameters
    - receipt_bytes: The proof receipt as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - boolean() | {:error, term()}: True if verification succeeds, false otherwise
  """
  @spec verify(list(byte()), list(byte())) ::
          boolean() | {:error, term()}
  defdelegate verify(receipt_bytes, elf),
    to: Risc0.AarmRustler,
    as: :verify

  @doc """
  Generates a resource with the given parameters.

  ## Parameters
    - label: Resource label as bytes
    - nonce: Nonce value as bytes
    - quantity: Resource quantity as bytes
    - data: Resource value as bytes
    - eph: Boolean flag indicating if resource is ephemeral
    - npk: Nullifier spending key as bytes
    - logic: Image identifier as bytes
    - rseed: Random seed as bytes

  ## Returns
    - list(byte()) | {:error, term()}: The generated resource as bytes or an error
  """
  @spec generate_resource(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    boolean(),
    list(byte()),
    list(byte()),
    list(byte()))  ::
    list(byte()) | {:error, term()}
  defdelegate generate_resource(
    label,
    nonce,
    quantity,
    data,
    eph,
    npk,
    logic,
    rseed),
    to: Risc0.AarmRustler,
    as: :generate_resource

  @doc """
  Generates a compliance circuit for resource transfer verification.

  ## Parameters
    - input_resource: Input resource data as bytes
    - output_resource: Output resource data as bytes
    - rcv: Resource commitment value as bytes
    - merkle_path: Merkle path proof as bytes
    - npk: Nullifier spending key as bytes

  ## Returns
    - list(byte()) | {:error, term()}: The generated circuit as bytes or an error
  """
  @spec generate_compliance_witness(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())
  ) :: list(byte()) | {:error, term()}
  defdelegate generate_compliance_witness(
    input_resource,
    output_resource,
    rcv,
    merkle_path,
    npk
  ), to: Risc0.AarmRustler, as: :generate_compliance_witness

  @spec get_compliance_instance(list(byte())) ::
    {list(byte()), list(byte()), list(byte()), list(byte()), list(byte())} | {:error, term()}
  defdelegate get_compliance_instance(receipt_bytes), to: Risc0.AarmRustler, as: :get_compliance_instance

  @doc """
  Generates 32 random bytes.

  ## Returns
    - list(byte()) | {:error, term()}: 32 random bytes or an error
  """
  @spec random_32() :: list(byte()) | {:error, term()}
  defdelegate random_32(), to: Risc0.AarmRustler, as: :random_32

  @doc """
  Generates a 32-level Merkle path.

  ## Returns
    - list(byte()) | {:error, term()}: The generated Merkle path as bytes or an error
  """
  @spec random_merkle_path_32() :: list(byte()) | {:error, term()}
  defdelegate random_merkle_path_32(), to: Risc0.AarmRustler, as: :random_merkle_path_32

  @doc """
  Generates a nullifier spending key.

  ## Returns
    - list(byte()) | {:error, term()}: The generated npk as bytes or an error
  """
  @spec random_nsk() :: list(byte()) | {:error, term()}
  defdelegate random_nsk(), to: Risc0.AarmRustler, as: :random_nsk

  @doc """
  Generates a nullifier public key from a nullifier spending key.
  """
  @spec generate_npk(list(byte())) :: list(byte()) | {:error, term()}
  defdelegate generate_npk(nsk), to: Risc0.AarmRustler, as: :generate_npk

  @doc """
  Encrypts a message using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - message: The message to encrypt as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes for encryption

  ## Returns
    - list(byte()) | {:error, term()}: The encrypted ciphertext as bytes or an error
  """
  @spec encrypt(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())
  ) :: list(byte()) | {:error, term()}
  defdelegate encrypt(
    message,
    pk_bytes,
    sk_bytes,
    nonce_bytes
  ), to: Risc0.AarmRustler, as: :encrypt

  @doc """
  Decrypts a ciphertext using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - cipher: The ciphertext to decrypt as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes used for encryption

  ## Returns
    - list(byte()) | {:error, term()}: The decrypted plaintext as bytes or an error
  """
  @spec decrypt(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())
  ) :: list(byte()) | {:error, term()}
  defdelegate decrypt(
    cipher,
    pk_bytes,
    sk_bytes,
    nonce_bytes
  ), to: Risc0.AarmRustler, as: :decrypt

  @doc """
  Generates a random private key and its corresponding public key.

  ## Returns
    - {list(byte()), list(byte())} | {:error, term()}: A tuple containing the private key bytes
      and public key bytes, or an error
  """
  @spec random_keypair() :: {list(byte()), list(byte())} | {:error, term()}
  defdelegate random_keypair(), to: Risc0.AarmRustler, as: :random_keypair
  @doc """
  Computes SHA256 hash of a single input.

  ## Parameters
    - input: Input bytes to hash

  ## Returns
    - list(byte()) | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_single(list(byte())) :: list(byte()) | {:error, term()}
  defdelegate sha256_single(input), to: Risc0.AarmRustler, as: :sha256_single

  @doc """
  Computes SHA256 hash of two inputs concatenated.

  ## Parameters
    - x: First input bytes
    - y: Second input bytes

  ## Returns
    - list(byte()) | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_double(list(byte()), list(byte())) :: list(byte()) | {:error, term()}
  defdelegate sha256_double(x, y), to: Risc0.AarmRustler, as: :sha256_double

  @doc """
  Computes SHA256 hash of multiple inputs concatenated.

  ## Parameters
    - inputs: List of byte lists to hash

  ## Returns
    - list(byte()) | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_many(list(list(byte()))) :: list(byte()) | {:error, term()}
  defdelegate sha256_many(inputs), to: Risc0.AarmRustler, as: :sha256_many
end
