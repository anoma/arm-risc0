# NIF for Elixir.Risc0

## To build the NIF module:

- Your NIF will now build along with your project.

## To load the NIF:

```elixir
defmodule Risc0 do
  use Rustler, otp_app: :anoma, crate: "risc0"

  # When your NIF is loaded, it will override this function.
  def risc0_prove(_arg1, _arg2, _arg3), do: :erlang.nif_error(:nif_not_loaded)
  def risc0_verify(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
end
```

A full example can be found in [risc0_vm/README.md](../risc0_vm/README.md)