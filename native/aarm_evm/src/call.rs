use alloy::sol;
use tokio;

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use dotenv::dotenv;
use std::env;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ProtocolAdapter,
    "src/ProtocolAdapter.json"
);

async fn get_latest_root() -> B256 {
    dotenv().ok();

    let signer = env::var("PRIVATE_KEY")
        .expect("Couldn't read PRIVATE_KEY")
        .parse::<PrivateKeySigner>()
        .expect("Wrong private key format");

    let rpc_url = format!(
        "https://sepolia.infura.io/v3/{}",
        env::var("API_KEY_INFURA").expect("Couldn't read API_KEY_INFURA")
    );

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .on_http(rpc_url.parse().expect("Failed to parse RPC URL"));

    let protocol_adapter = env::var("PROTOCOL_ADAPTER_ADDRESS_SEPOLIA")
        .expect("Couldn't read PROTOCOL_ADAPTER_ADDRESS_SEPOLIA")
        .parse::<Address>()
        .expect("Wrong address format");

    println!("{:?}", provider.get_block_number().await);

    let contract = ProtocolAdapter::new(protocol_adapter, provider);

    contract.latestRoot().call().await.unwrap().root
}

#[tokio::test]
async fn rpc_call() {
    use alloy::primitives::Address;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::signers::local::PrivateKeySigner;
    use dotenv::dotenv;
    use std::env;

    dotenv().ok();

    let signer = env::var("PRIVATE_KEY")
        .expect("Couldn't read PRIVATE_KEY")
        .parse::<PrivateKeySigner>()
        .expect("Wrong private key format");

    let rpc_url = format!(
        "https://sepolia.infura.io/v3/{}",
        env::var("API_KEY_INFURA").expect("Couldn't read API_KEY_INFURA")
    );

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .on_http(rpc_url.parse().expect("Failed to parse RPC URL"));

    let protocol_adapter = env::var("PROTOCOL_ADAPTER_ADDRESS_SEPOLIA")
        .expect("Couldn't read PROTOCOL_ADAPTER_ADDRESS_SEPOLIA")
        .parse::<Address>()
        .expect("Wrong address format");

    println!("{:?}", provider.get_block_number().await);

    let contract = ProtocolAdapter::new(protocol_adapter, provider);
    println!(
        "latest root: {:?}",
        contract.latestRoot().call().await.unwrap().root
    );
}
