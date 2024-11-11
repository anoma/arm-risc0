defmodule Risc0.AarmRustler do
  use Rustler, otp_app: :risc0, crate: :aarm_rustler

  @moduledoc """
  Provides NIF functions for Risc0 proof generation, verification, and related cryptographic operations.
  This module contains the low-level Rust NIF bindings for zero-knowledge proofs and encryption.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @doc """
  Generates a zero-knowledge proof for the given environment and ELF binary.

  ## Parameters
    - env_bytes: The environment data as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The proof receipt as bytes or an error
  """
  @spec prove(list(byte()), list(byte())) ::
          nif_result({list(byte())})
  def prove(_env_bytes, _elf), do: error()

  @doc """
  Verifies a zero-knowledge proof receipt against an ELF binary.

  ## Parameters
    - receipt_bytes: The proof receipt as a list of bytes
    - elf: The ELF binary as a list of bytes

  ## Returns
    - {:ok, boolean()} | {:error, term()}: True if verification succeeds, false otherwise
  """
  @spec verify(list(byte()), list(byte())) :: nif_result(boolean())
  def verify(_receipt_bytes, _elf), do: error()

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
    - {:ok, list(byte())} | {:error, term()}: The generated resource as bytes or an error
  """
  @spec generate_resource(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    boolean(),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_resource(
    _label,
    _nonce,
    _quantity,
    _data,
    _eph,
    _npk,
    _logic,
    _rseed
  ), do: error()

  @doc """
  Generates a compliance circuit for resource transfer verification.

  ## Parameters
    - input_resource: Input resource data as bytes
    - output_resource: Output resource data as bytes
    - rcv: Resource commitment value as bytes
    - merkle_path: Merkle path proof as bytes
    - npk: Nullifier spending key as bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated circuit as bytes or an error
  """
  @spec generate_compliance_witness(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_compliance_witness(
    _input_resource,
    _output_resource,
    _rcv,
    _merkle_path,
    _npk
  ), do: error()

  @doc """
  Generates 32 random bytes.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: 32 random bytes or an error
  """
  @spec random_32() :: nif_result(list(byte()))
  def random_32(), do: error()

  @doc """
  Generates a 32-level Merkle path.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated Merkle path as bytes or an error
  """
  @spec random_merkle_path_32() ::  nif_result(list(byte()))
  def random_merkle_path_32(), do: error()

  @doc """
  Generates a nullifier spending key.

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated npk as bytes or an error
  """
  @spec random_nsk() :: nif_result(list(byte()))
  def random_nsk(), do: error()

  @doc """
  Generates a nullifier public key from a nullifier spending key.

  ## Parameters
    - nsk: Nullifier secret key as bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The generated npk as bytes or an error
  """
  @spec generate_npk(list(byte())) :: nif_result(list(byte()))
  def generate_npk(_nsk), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Encrypts a message using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - message: The message to encrypt as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes for encryption

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The encrypted message as bytes or an error
  """
  @spec encrypt(list(byte()), list(byte()), list(byte()), list(byte())) :: nif_result(list(byte()))
  def encrypt(_message, _pk_bytes, _sk_bytes, _nonce_bytes), do: error()

  @doc """
  Decrypts a message using AES-256-GCM with the given keys and nonce.

  ## Parameters
    - cipher: The encrypted message as bytes
    - pk_bytes: Public key bytes
    - sk_bytes: Secret key bytes
    - nonce_bytes: Nonce bytes used for encryption

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The decrypted message as bytes or an error
  """
  @spec decrypt(list(byte()), list(byte()), list(byte()), list(byte())) :: nif_result(list(byte()))
  def decrypt(_cipher, _pk_bytes, _sk_bytes, _nonce_bytes), do: error()

  @doc """
  Generates a public/private keypair for encryption.

  ## Returns
    - {:ok, {list(byte()), list(byte())}} | {:error, term()}: A tuple containing the secret key and public key bytes
  """
  @spec random_keypair() :: nif_result({list(byte()), list(byte())})
  def random_keypair(), do: error()


  @doc """
  Computes SHA256 hash of a single input.

  ## Parameters
    - input: Input bytes to hash

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_single(list(byte())) :: nif_result(list(byte()))
  def sha256_single(_input), do: error()

  @doc """
  Computes SHA256 hash of two inputs concatenated.

  ## Parameters
    - x: First input bytes
    - y: Second input bytes

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_double(list(byte()), list(byte())) :: nif_result(list(byte()))
  def sha256_double(_x, _y), do: error()

  @doc """
  Computes SHA256 hash of multiple inputs concatenated.

  ## Parameters
    - inputs: List of byte lists to hash

  ## Returns
    - {:ok, list(byte())} | {:error, term()}: The SHA256 hash as bytes or an error
  """
  @spec sha256_many(list(list(byte()))) :: nif_result(list(byte()))
  def sha256_many(_inputs), do: error()


end
