defmodule Risc0 do
  # @spec risc0_vm_runner(binary(), binary()) ::
  #         {binary(), [byte()], [byte()], [byte()]} | {:error, term()}
  # defdelegate risc0_vm_runner(program_content, program_input),
  #   to: Risc0.Risc0VM,
  #   as: :risc0_vm_runner

  @spec prove([byte()], [byte()]) ::
          {[byte()]} | {:error, term()}
  defdelegate prove(env_bytes, elf),
    to: Risc0.Risc0Prover,
    as: :risc0_prove

  @spec verify(list(byte()), list(byte())) ::
          boolean() | {:error, term()}
  defdelegate verify(receipt_bytes, elf),
    to: Risc0.Risc0Prover,
    as: :risc0_verify

  # @spec get_output(list(byte())) ::
  #         any() | {:error, term()}
  # defdelegate get_output(pub_input),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_get_output

  # @spec sign(list(byte()), list(list(byte()))) ::
  #         list(byte()) | {:error, term()}
  # defdelegate sign(private_key_segments, messages),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_binding_sig_sign

  # @spec sig_verify(list(list(byte())), list(list(byte())), list(byte())) ::
  #         boolean() | {:error, term()}
  # defdelegate sig_verify(pub_key_segments, messages, signature),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_binding_sig_verify

  # @spec random_felt() ::
  #         list(byte()) | {:error, term()}
  # defdelegate random_felt(),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_random_felt

  # @spec get_public_key(list(byte())) ::
  #         list(byte()) | {:error, term()}
  # defdelegate get_public_key(priv_key),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_get_binding_sig_public_key

  # @spec sha256(list(byte()), list(byte())) ::
  #         list(byte()) | {:error, term()}
  # defdelegate sha256(x, y),
  #   to: Risc0.Risc0Prover,
  #   as: :sha256

  # @spec get_program_hash(list(byte())) ::
  #         list(byte()) | {:error, term()}
  # defdelegate get_program_hash(pub_input),
  #   to: Risc0.Risc0Prover,
  #   as: :program_hash

  # @spec felt_to_string(list(byte())) :: binary()
  # defdelegate felt_to_string(felt),
  #   to: Risc0.Risc0Prover,
  #   as: :risc0_felt_to_string

  @spec generate_compliance_input_json(
          list(byte()),
          list(byte()),
          list(list(byte())),
          integer(),
          list(byte()),
          list(byte()),
          list(byte())
        ) ::
          binary()
  defdelegate generate_compliance_input_json(
                input_resource,
                output_resource,
                path,
                position,
                input_nf_key,
                eph_root,
                rcv
              ),
              to: Risc0.Risc0Prover,
              as: :risc0_generate_compliance_input_json
end
