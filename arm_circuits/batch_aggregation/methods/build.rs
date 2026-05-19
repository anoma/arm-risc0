use std::collections::HashMap;

use risc0_build::GuestOptionsBuilder;

fn main() {
    let guest_features = if cfg!(feature = "borsh") {
        vec!["borsh".to_string()]
    } else if cfg!(feature = "evm") {
        vec!["evm".to_string()]
    } else {
        vec![]
    };

    let opts = GuestOptionsBuilder::default()
        .features(guest_features)
        .build()
        .unwrap();

    risc0_build::embed_methods_with_options(HashMap::from([("batch-aggregation-guest", opts)]));
}
