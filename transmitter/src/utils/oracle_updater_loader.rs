use std::io::BufReader;
use std::{env, fs::File};

use std::str::FromStr;

use anchor_lang::prelude::Pubkey;
use anyhow::Result;
use serde_json::{self, Value};

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
