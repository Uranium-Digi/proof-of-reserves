mod modes;
use modes::directapi;
use modes::websocket;

use transmitter::transmitter::Transmitter;
use utils::wallet_loader::load_funding_wallet;

mod transmitter;
mod utils;

// use crate::verifier::loader::OracleUpdaterProgram;
use anchor_client::solana_sdk::{commitment_config::CommitmentConfig, signer::Signer};

use std::env;

const DEFAULT_FEED_ID: &str = "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok(); // loads .env file automatically

    let report = directapi::run().await?;

    let wallet = load_funding_wallet()?;
    println!("🔑 Loaded wallet pubkey: {}", wallet.pubkey());

    let transmitter = Transmitter::new(CommitmentConfig::confirmed())?;

    transmitter.verify(&report.full_report).await?;

    Ok(())
}

// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     dotenv::dotenv().ok(); // loads .env file automatically

//     let args: Vec<String> = env::args().collect();
//     if args.len() < 2 {
//         eprintln!("Usage: cargo run [mode: directapi|websocket] [feed_id (optional)]");
//         std::process::exit(1);
//     }

//     let mode = &args[1];
//     let default_feed_id = DEFAULT_FEED_ID.to_string();
//     let feed_id = args.get(2).unwrap_or(&default_feed_id);

//     match mode.as_str() {
//         "directapi" => directapi::run(feed_id).await?,
//         "websocket" => websocket::run(feed_id).await?,
//         _ => {
//             eprintln!("Unknown mode: {}", mode);
//             std::process::exit(1);
//         }
//     }

//     let wallet = load_funding_wallet()?;
//     println!("🔑 Loaded wallet pubkey: {}", wallet.pubkey());

//     // let verifier = Verifier::new(CommitmentConfig::confirmed())?;

//     // verifier.verify().await?;

//     Ok(())
// }
