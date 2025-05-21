use std::io::BufReader;
use std::rc::Rc;
use std::{env, fs::File};

use std::str::FromStr;

use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::{Cluster, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::Result;
use serde_json::{self, Value};

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

pub fn load_oracle_updater_program_id() -> Pubkey {
    oracle_updater::ID
}

pub fn load_oracle_updater(
    cluster: Option<Cluster>,
    route_type: RouteType,
    wallet_path_name: Option<String>,
) -> Result<(Program<Rc<Keypair>>, Pubkey)> {
    let (client, provider) = get_client_and_provider(cluster, wallet_path_name)?;

    let program_id = load_oracle_updater_program_id();
    let program: Program<Rc<Keypair>>;

    if route_type == RouteType::Client {
        program = client.program(program_id).unwrap();
    } else {
        program = provider.program(program_id).unwrap();
    }

    Ok((program, program_id))
}
