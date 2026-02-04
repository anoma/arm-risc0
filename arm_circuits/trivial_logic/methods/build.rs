fn main() {
    let mut features = Vec::new();
    if cfg!(feature = "borsh") {
        features.push("borsh".to_string());
    }
    if cfg!(feature = "bin") {
        features.push("bin".to_string());
    }
    if cfg!(feature = "evm") {
        features.push("evm".to_string());
    }

    if features.is_empty() {
        risc0_build::embed_methods();
    } else {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "trivial-logic-guest",
            risc0_build::GuestOptionsBuilder::default()
                .features(features)
                .build()
                .unwrap(),
        );
        risc0_build::embed_methods_with_options(options);
    }
}
