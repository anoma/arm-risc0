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
    list(byte()),
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

  # @spec get_output(list(byte())) :: nif_result(list(byte()))
  # def get_output(_env_bytes), do: error()
  # @spec risc0_binding_sig_sign(list(list(byte())), list(list(byte()))) ::
  #         nif_result(list(byte()))
  # def risc0_binding_sig_sign(_private_key_segments, _messages), do: error()

  # @spec risc0_binding_sig_verify(
  #         list(list(byte())),
  #         list(list(byte())),
  #         list(byte())
  #       ) :: nif_result(boolean())
  # def risc0_binding_sig_verify(_pub_key_segments, _messages, _signature),
  #   do: error()

  # @spec risc0_random_felt() :: nif_result(list(byte()))
  # def risc0_random_felt(), do: error()

  # @spec risc0_get_binding_sig_public_key(list(byte())) ::
  #         nif_result(list(byte()))
  # def risc0_get_binding_sig_public_key(_priv_key), do: error()

  # @spec sha256(list(byte()), list(byte())) :: nif_result(list(byte()))
  # def sha256(_x, _y), do: error()

  # @spec program_hash(list(byte())) :: nif_result(list(byte()))
  # def program_hash(_public_inputs), do: error()

  # def risc0_felt_to_string(_felt), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end

# defmodule Risc0.Risc0VM do
#   use Rustler,
#     otp_app: :risc0,
#     crate: :risc0_vm

#   @moduledoc """
#   Documentation for `Risc0VM`.
#   """
#   @typedoc "Result type for NIF functions that can return errors"
#   @type nif_result(t) :: t | {:error, term()}

#   # When loading a NIF module, dummy clauses for all NIF function are required.
#   # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
#   @spec risc0_vm_runner(binary(), binary()) ::
#           nif_result({binary(), list(byte()), list(byte()), list(byte())})
#   def risc0_vm_runner(_program_content, _program_inputs),
#     do: :erlang.nif_error(:nif_not_loaded)
# end
