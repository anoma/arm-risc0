use std::collections::HashMap;

use risc0_build::GuestOptionsBuilder;

fn main() {
    let guest_features = if cfg!(feature = "abi_encoding") {
        vec!["abi_encoding".to_string()]
    } else {
        vec![]
    };

    let opts = GuestOptionsBuilder::default()
        .features(guest_features)
        .build()
        .unwrap();

    risc0_build::embed_methods_with_options(HashMap::from([("batch-aggregation-guest", opts)]));
}
