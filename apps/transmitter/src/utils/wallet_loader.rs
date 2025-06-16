use anchor_client::solana_sdk::signature::{read_keypair_file, Keypair};
use anyhow::{Context, Error, Result};
use std::path::Path;

/// Loads a funding wallet from the `.secrets/fundingWallet.json` file
pub fn load_funding_wallet(wallet_path_name: Option<String>) -> Result<Keypair> {
    if let Some(wallet_path_name) = wallet_path_name {
        load_wallet_from_path(&wallet_path_name)
    } else {
        load_wallet_from_path("FUNDING_WALLET_PATH")
    }
}

fn load_wallet_from_path(wallet_path_name: &str) -> Result<Keypair> {
    let wallet_path = std::env::var(wallet_path_name).context(format!(
        "Failed to load wallet path from {}",
        wallet_path_name
    ))?;
    let path = Path::new(&wallet_path);

    let keypair = read_keypair_file(path)
        .map_err(|e| Error::msg(format!("Failed to read keypair: {}", e)))?;

    Ok(keypair)
}
