use alloy::providers::{Provider, ProviderBuilder};

use dotenv::dotenv;
use std::env;
use tokio;

#[tokio::test]
async fn rpc_call() {
    dotenv().ok();

    let rpc_url = format!(
        "https://sepolia.infura.io/v3/{}",
        env::var("API_KEY_INFURA").expect("Couldn't read API_KEY_INFURA")
    );

    let provider = ProviderBuilder::new().on_http(rpc_url.parse().expect("Failed to parse RPC URL"));
    
    let latest_block = provider.get_block_number().await;

    println!("Latest block number: {latest_block:?}");
}
