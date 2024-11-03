defmodule Risc0ComplianceTest do
  use ExUnit.Case

  @compliance_guest_elf File.read!("../compliance-circuit/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/compliance_guest")
  # If you change the compliance circuit, change `methods-0e48b529bacc479b` with the new hash.
  @compliance_guest_id File.read!("../compliance-circuit/target/debug/build/methods-0e48b529bacc479b/out/methods.rs")
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
    com_2 = [881554054, 1423722181, 2669433501, 1736387484, 1927038238, 3369494929, 2599234974, 1323892644]

    assert compliance_guest_id == com_2

    label = Risc0.random_32()
    nonce_1 = Risc0.random_32()
    nonce_2 = Risc0.random_32()
    quantity = Risc0.random_32()
    value = Risc0.random_32()
    eph = false
    nsk = Risc0.generate_nsk()
    rcv = Risc0.random_32()
    rseed_1 = Risc0.random_32()
    rseed_2 = Risc0.random_32()
    image_id = Risc0.random_32()
    merkle_path = Risc0.generate_merkle_path_32()

    input_resource = Risc0.generate_resource(
      label,
      nonce_1,
      quantity,
      value,
      eph,
      nsk,
      image_id,
      rseed_1
    )

    output_resource = Risc0.generate_resource(
      label,
      nonce_2,
      quantity,
      value,
      eph,
      nsk,
      image_id,
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
