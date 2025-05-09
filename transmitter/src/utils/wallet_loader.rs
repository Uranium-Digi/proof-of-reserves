use anchor_client::solana_sdk::signature::{Keypair, read_keypair_file};
use anyhow::{Error, Result};
use std::path::Path;
use std::rc::Rc;

/// Loads a funding wallet from the `.secrets/fundingWallet.json` file
pub fn load_funding_wallet() -> Result<Rc<Keypair>> {
    load_wallet_from_path("FUNDING_WALLET_PATH")
}

pub fn load_wallet_from_path(wallet_path_name: &str) -> Result<Rc<Keypair>> {
    let wallet_path = std::env::var(wallet_path_name).unwrap();
    let path = Path::new(&wallet_path);

    let keypair = read_keypair_file(path)
        .map_err(|e| Error::msg(format!("Failed to read keypair: {}", e)))?;

    Ok(Rc::new(keypair))
}
