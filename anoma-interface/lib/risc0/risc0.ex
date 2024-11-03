defmodule Risc0.Risc0Prover do
  use Rustler, otp_app: :risc0, crate: :risc0_prover


  @moduledoc """
  Provides NIF functions for Risc0 proof generation, verification, and related cryptographic operations.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @spec prove(list(byte()), list(byte())) ::
          nif_result({list(byte())})
  def prove(_env_bytes, _elf), do: error()

  @spec verify(list(byte()), list(byte())) :: nif_result(boolean())
  def verify(_receipt_bytes, _elf), do: error()

  @spec generate_resource(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(boolean()),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_resource(
    _label,
    _nonce,
    _quantity,
    _value,
    _eph,
    _nsk,
    _image_id,
    _rseed
  ), do: error()

  @spec generate_compliance_circuit(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte())) :: nif_result(list(byte()))
  def generate_compliance_circuit(
    _input_resource,
    _output_resource,
    _rcv,
    _merkle_path,
    _nsk
  ), do: error()

  @spec random_32() :: nif_result(list(byte()))
  def random_32(), do: error()

  @spec generate_merkle_path_32() ::  nif_result(list(byte()))
  def generate_merkle_path_32(), do: error()

  @spec generate_nsk() :: nif_result(list(byte()))
  def generate_nsk(), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end
