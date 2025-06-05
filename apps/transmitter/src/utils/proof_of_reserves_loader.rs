use std::rc::Rc;

use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::{Cluster, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::Result;

use super::config::get_client_and_provider;

#[derive(PartialEq)]
pub enum RouteType {
    Client,
    Provider,
}

impl Default for RouteType {
    fn default() -> Self {
        RouteType::Client
    }
}

pub fn load_proof_of_reserves_program_id() -> Pubkey {
    proof_of_reserves::ID
}

pub fn load_proof_of_reserves(
    cluster: Option<Cluster>,
    route_type: RouteType,
    signer: Rc<Keypair>,
) -> Result<(Program<Rc<Keypair>>, Pubkey)> {
    let (client, provider) = get_client_and_provider(cluster, signer)?;

    let program_id = load_proof_of_reserves_program_id();

    let program: Program<Rc<Keypair>> = match route_type {
        RouteType::Client => client,
        RouteType::Provider => provider,
    }
    .program(program_id)
    .unwrap();

    Ok((program, program_id))
}
