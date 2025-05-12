use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::solana_sdk::{commitment_config::CommitmentConfig, signer::Signer};
use anchor_client::{Client, Cluster};
use anyhow::Result;
use std::env;
use std::rc::Rc;

use crate::utils::wallet_loader::load_funding_wallet;

pub fn get_rpc_url() -> Result<String> {
    let rpc_url =
        env::var("RPC_URL").map_err(|_| anyhow::anyhow!("RPC_URL env variable is not set"))?;
    Ok(rpc_url)
}

pub fn get_client_and_provider() -> Result<(Client<Rc<Keypair>>, Client<Rc<Keypair>>)> {
    let rpc_url = get_rpc_url()?;
    let wallet = load_funding_wallet()?;
    let cluster = Cluster::Custom(rpc_url.clone(), rpc_url);

    let client = Client::new(Cluster::Devnet, Rc::clone(&wallet));
    //  We can also use the provider to create the program
    let commitment = CommitmentConfig::confirmed();
    let provider = Client::new_with_options(cluster, Rc::clone(&wallet), commitment);

    Ok((client, provider))
}

pub const DEFAULT_FEED_ID: &str =
    "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";
