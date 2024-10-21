defmodule Risc0.Risc0Prover do
  use Rustler,
    otp_app: :risc0,
    crate: :risc0_prover

  @moduledoc """
  Provides NIF functions for Risc0 proof generation, verification, and related cryptographic operations.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @spec risc0_prove(list(byte()), list(byte())) ::
          nif_result({list(byte())})
  def risc0_prove(_env_bytes, _elf), do: error()

  @spec risc0_verify(list(byte()), list(byte())) :: nif_result(boolean())
  def risc0_verify(_receipt_bytes, _elf), do: error()

  # @spec risc0_get_output(list(byte())) :: nif_result(list(list(byte())))
  # def risc0_get_output(_public_input), do: error()

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

  def risc0_generate_compliance_input_json(
        _input_resource,
        _output_resource,
        _path,
        _position,
        _input_nf_key,
        _eph_root,
        _rcv
      ),
      do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end

defmodule Risc0.Risc0VM do
  use Rustler,
    otp_app: :risc0,
    crate: :risc0_vm

  @moduledoc """
  Documentation for `Risc0VM`.
  """
  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  # When loading a NIF module, dummy clauses for all NIF function are required.
  # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
  @spec risc0_vm_runner(binary(), binary()) ::
          nif_result({binary(), list(byte()), list(byte()), list(byte())})
  def risc0_vm_runner(_program_content, _program_inputs),
    do: :erlang.nif_error(:nif_not_loaded)
end
