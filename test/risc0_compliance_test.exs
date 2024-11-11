defmodule Risc0ComplianceTest do
  use ExUnit.Case

  @compliance_guest_elf File.read!("native/examples/compliance_circuit/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/compliance_guest")
  # If you change the compliance circuit, change `methods-0e48b529bacc479b` with the new hash.
  @compliance_guest_id File.read!("native/examples/compliance_circuit/target/debug/build/methods-2dacd0d24f782198/out/methods.rs")
                       |> String.split("\n")
                       |> Enum.find(&String.contains?(&1, "COMPLIANCE_GUEST_ID"))
                       |> String.split("= [")  # Split on "= [" to get everything after the array start
                       |> Enum.at(1)
                       |> String.split("];")   # Split on "];" to remove the array end
                       |> Enum.at(0)
                       |> String.split(",")
                       |> Enum.map(&String.trim/1)
                       |> Enum.map(&String.to_integer/1)

  @tag timeout: :infinity
  test "compliance_circuit" do
    compliance_guest_elf = @compliance_guest_elf |> :binary.bin_to_list()
    compliance_guest_id = @compliance_guest_id
    label = Risc0.random_32()
    nonce_1 = Risc0.random_32()
    nonce_2 = Risc0.random_32()
    quantity = Risc0.random_32()
    data = Risc0.random_32()
    eph = false
    nsk = Risc0.random_nsk()
    npk = Risc0.generate_npk(nsk)
    rcv = Risc0.random_32()
    rseed_1 = Risc0.random_32()
    rseed_2 = Risc0.random_32()
    logic = Risc0.random_32()
    merkle_path = Risc0.random_merkle_path_32()

    input_resource = Risc0.generate_resource(
      label,
      nonce_1,
      quantity,
      data,
      eph,
      npk,
      logic,
      rseed_1
    )

    output_resource = Risc0.generate_resource(
      label,
      nonce_2,
      quantity,
      data,
      eph,
      npk,
      logic,
      rseed_2
    )

    compliance_circuit = Risc0.generate_compliance_circuit(
      input_resource,
      output_resource,
      rcv,
      merkle_path,
      nsk
    )

    # Prove and verify
    receipt = Risc0.prove(compliance_circuit, compliance_guest_elf)
    verify = Risc0.verify(receipt, compliance_guest_id)
    assert true == verify
  end
end
