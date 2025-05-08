use anchor_client::solana_sdk::signature::{Keypair, read_keypair_file};
use anyhow::{Error, Result};
use std::path::Path;
use std::rc::Rc;

/// Loads a funding wallet from the `.secrets/fundingWallet.json` file
pub fn load_funding_wallet() -> Result<Rc<Keypair>> {
    let path = Path::new("../.secrets/fundingWallet.json");

    let keypair = read_keypair_file(path)
        .map_err(|e| Error::msg(format!("Failed to read keypair: {}", e)))?;

    println!("keypair: {:?}", keypair);
    Ok(Rc::new(keypair))
}
