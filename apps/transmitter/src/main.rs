mod modes;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::Cluster;
use anchor_lang::prelude::Pubkey;
use app_config::AppConfig;
use modes::websocket;

use tracing::info;
use tracing_subscriber::EnvFilter;
use transmitter::transmitter::Transmitter;

pub mod app_config;
pub mod transmitter;
pub mod utils;

use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with UTC timestamps
    if let Ok(level) = std::env::var("RUST_LOG") {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(&format!(
                "{}={level}",
                env!("CARGO_PKG_NAME").replace("-", "_"),
            )))
            .init();
    }
    // load app config
    let app_config = AppConfig::new().await;

    // prepare signer, program ids and cluster
    let cluster = Cluster::Custom(
        app_config.rpc_url.clone(),                         // https url
        app_config.clone().rpc_url.replace("https", "wss"), // wss url - needed for websocket
    );
    let signer = Keypair::from_base58_string(&app_config.signer_private_key);
    let proof_of_reserves_program_id =
        Pubkey::from_str(&app_config.program_id).expect("Invalid Proof of Reserves Program ID");
    let chainlink_verifier_program_id = Pubkey::from_str(&app_config.chainlink_verifier_program_id)
        .expect("Invalid Chainlink Verifier Program ID");
    let access_controller_program_id = Pubkey::from_str(&app_config.access_controller_program_id)
        .expect("Invalid Access Controller Program ID");
    let u_address = Pubkey::from_str(&app_config.u_address).expect("Invalid U Address");
    let access_controller_data_account =
        Pubkey::from_str(&app_config.access_controller_data_account)
            .expect("Invalid Access Controller Data Account");

    // create transmitter
    let transmitter = Transmitter::new(
        cluster,
        Arc::new(signer),
        proof_of_reserves_program_id,
        u_address,
        chainlink_verifier_program_id,
        access_controller_program_id,
        access_controller_data_account,
    )?;

    // run
    let handle = websocket::run(&app_config, transmitter).await?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
            handle.abort();
        }
    }
    Ok(())
}

// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     dotenv::dotenv().ok(); // loads .env file automatically

//     let report = directapi::run().await?;

//     let wallet = load_funding_wallet()?;
//     println!("🔑 Loaded wallet pubkey: {}", wallet.pubkey());

//     let transmitter = Transmitter::new()?;

//     transmitter.verify(&report.full_report).await?;

//     Ok(())
// }

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
