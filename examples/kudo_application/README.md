# Kudo Example
Note: The succinct STARK proof is used by default. You can use the feature flag(groth16_prover) to generate Groth16 proofs.

## Run tests
```bash
cargo test --release -- --nocapture generate_an_issue_tx
cargo test --release -- --nocapture generate_a_burn_tx
cargo test --release -- --nocapture generate_a_transfer_tx
cargo test --release -- --nocapture generate_a_swap_tx
```

## Performance on Bonsai
You can also run tests locally, although it may take some time.

### Set Bonsai environment variables
You can request a Bonsai API key from [here](https://risczero.com/bonsai)

```bash
export BONSAI_API_URL=https://api.bonsai.xyz/
export BONSAI_API_KEY=YOUR_KEY_REQUESTED_FROM_BONSAI
```

### Issue
Tx build duration time: 86.193917417s

TX verify duration time: 98.132167ms

### Burn
Tx build duration time: 56.230887792s

TX verify duration time: 72.716125ms

### Transfer
Tx build duration time: 89.415549209s

TX verify duration time: 100.321959ms

### Swap
Tx build duration time: 88.474378292s

TX verify duration time: 175.762875ms