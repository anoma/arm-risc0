use std::collections::HashMap;
use risc0_build::GuestOptionsBuilder;

fn main() {
    let features = if cfg!(feature = "borsh") {
        vec!["borsh".into()]
    } else if cfg!(feature = "bin") {
        vec!["bin".into()]
    } else {
        vec![]
    };

    let map = HashMap::from([(
        "batch_aggregation",
        GuestOptionsBuilder::default()
            .features(features)
            .build()
            .unwrap(),
    )]);

    risc0_build::embed_methods_with_options(map);
}
