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

pub fn load_oracle_updater_programId() -> Result<Pubkey> {
    // let idl_path = "../oracle-updater/target/idl/oracle_updater.json";
    let idl_path = env::var("ORACLE_UPDATER_IDL_PATH").unwrap();
    println!("idl_path: {}", idl_path);
    let file =
        File::open(idl_path).map_err(|e| anyhow::anyhow!("Failed to open IDL file: {}", e))?;
    let reader = BufReader::new(file);
    let idl: Value = serde_json::from_reader(reader)
        .map_err(|e| anyhow::anyhow!("Failed to parse IDL JSON: {}", e))?;

    let program_id_str = idl["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Program ID not found in IDL metadata"))?;
    let program_id = Pubkey::from_str(program_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse program ID: {}", e))?;

    Ok(program_id)
}

pub fn load_oracle_updater(
    cluster: Option<Cluster>,
    route_type: RouteType,
) -> Result<(Program<Rc<Keypair>>, Pubkey)> {
    let (client, provider) = get_client_and_provider(cluster)?;

    let program_id = load_oracle_updater_programId()?;
    let program: Program<Rc<Keypair>>;

    if route_type == RouteType::Client {
        program = client.program(program_id).unwrap();
    } else {
        program = provider.program(program_id).unwrap();
    }

    Ok((program, program_id))
}
