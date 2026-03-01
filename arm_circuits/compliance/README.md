# Compliance circuit
Note: The succinct STARK proof is used by default.

## Run the circuit
```bash
cargo run --release
```

## Performance on Bonsai
You can also run tests locally, although it may take some time.

### Set Bonsai environment variables
You can request a Bonsai API key from [here](https://risczero.com/bonsai)

```bash
export BONSAI_API_URL=https://api.bonsai.xyz/
export BONSAI_API_KEY=YOUR_KEY_REQUESTED_FROM_BONSAI
```

### Bench result(Bonsai)
Prove duration time: 13.310000041s

Verify duration time: 13.435ms

### Bench result(local CPU)
Prove duration time: 86.101263s
Extract Journal duration time: 709ns
Verify duration time: 11.469333ms
  Total cycles:     1310720
  User cycles:      1092294