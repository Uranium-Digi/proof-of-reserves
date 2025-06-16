use std::sync::Arc;

use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::{Client, Cluster, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::Result;

pub fn load_proof_of_reserves(
    program_id: Pubkey,
    cluster: Cluster,
    signer: Arc<Keypair>,
) -> Result<Program<Arc<Keypair>>> {
    let client = Client::new_with_options(cluster, signer, CommitmentConfig::confirmed());
    client
        .program(program_id)
        .map_err(|e| anyhow::anyhow!("Failed to load Proof of Reserves program: {}", e))
}
