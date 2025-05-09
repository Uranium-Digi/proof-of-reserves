mod modes;
use modes::directapi;
use modes::websocket;
use wallet_loader::load_funding_wallet;

mod transmitter;
mod verifier;
mod wallet_loader;
use crate::verifier::loader::Verifier;
// use crate::verifier::loader::OracleUpdaterProgram;
use anchor_client::solana_sdk::{commitment_config::CommitmentConfig, signer::Signer};
use std::env;

const DEFAULT_FEED_ID: &str = "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok(); // loads .env file automatically

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run [mode: directapi|websocket] [feed_id (optional)]");
        std::process::exit(1);
    }

    let mode = &args[1];
    let default_feed_id = DEFAULT_FEED_ID.to_string();
    let feed_id = args.get(2).unwrap_or(&default_feed_id);

    match mode.as_str() {
        "directapi" => directapi::run(feed_id).await?,
        "websocket" => websocket::run(feed_id).await?,
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }

    let wallet = load_funding_wallet()?;
    println!("🔑 Loaded wallet pubkey: {}", wallet.pubkey());

    // let verifier = Verifier::new(CommitmentConfig::confirmed())?;

    // verifier.verify().await?;

    Ok(())
}

// use chainlink_data_streams_report::feed_id::ID;
// use chainlink_data_streams_report::report::{decode_full_report, v3::ReportDataV3}; // Import the v3 report schema for Crypto streams
// use chainlink_data_streams_sdk::config::Config;
// use chainlink_data_streams_sdk::stream::Stream;
// use dotenv::dotenv;
// use std::env;
// use std::error::Error;
// use tracing::{info, warn};
// use tracing_subscriber::fmt::time::UtcTime;

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     dotenv().ok();
//     // Initialize logging with UTC timestamps
//     tracing_subscriber::fmt()
//         .with_timer(UtcTime::rfc_3339())
//         .with_max_level(tracing::Level::INFO)
//         .init();

//     // Get feed IDs from command line arguments
//     let args: Vec<String> = env::args().collect();
//     if args.len() < 2 {
//         eprintln!("Usage: cargo run [StreamID1] [StreamID2] ...");
//         std::process::exit(1);
//     }

//     // Get API credentials from environment variables
//     let api_key = env::var("API_KEY").expect("API_KEY must be set");
//     let api_secret = env::var("API_SECRET").expect("API_SECRET must be set");

//     // Parse feed IDs from command line arguments
//     let mut feed_ids = Vec::new();
//     for arg in args.iter().skip(1) {
//         let feed_id = ID::from_hex_str(arg)?;
//         feed_ids.push(feed_id);
//     }

//     // Initialize the configuration
//     let config = Config::new(
//         api_key,
//         api_secret,
//         "https://api.testnet-dataengine.chain.link".to_string(),
//         "wss://ws.testnet-dataengine.chain.link".to_string(),
//     )
//     .build()?;

//     // Create and initialize the stream
//     let mut stream = Stream::new(&config, feed_ids).await?;
//     stream.listen().await?;

//     info!("WebSocket connection established. Listening for reports...");

//     // Process incoming reports
//     loop {
//         match stream.read().await {
//             Ok(response) => {
//                 info!("\nRaw report data: {:?}\n", response.report);

//                 // Decode the report
//                 let full_report = hex::decode(&response.report.full_report[2..])?;
//                 let (_report_context, report_blob) = decode_full_report(&full_report)?;
//                 let report_data = ReportDataV3::decode(&report_blob)?;

//                 // Print decoded report details
//                 info!(
//                     "\n--- Report Stream ID: {} ---\n\
//                      ------------------------------------------\n\
//                      Observations Timestamp : {}\n\
//                      Price                 : {}\n\
//                      Bid                   : {}\n\
//                      Ask                   : {}\n\
//                      Valid From Timestamp  : {}\n\
//                      Expires At           : {}\n\
//                      Link Fee             : {}\n\
//                      Native Fee           : {}\n\
//                      ------------------------------------------",
//                     response.report.feed_id.to_hex_string(),
//                     response.report.observations_timestamp,
//                     report_data.benchmark_price,
//                     report_data.bid,
//                     report_data.ask,
//                     response.report.valid_from_timestamp,
//                     report_data.expires_at,
//                     report_data.link_fee,
//                     report_data.native_fee,
//                 );

//                 // Print stream stats
//                 info!(
//                     "\n--- Stream Stats ---\n{:#?}\n\
//                      --------------------------------------------------------------------------------------------------------------------------------------------",
//                     stream.get_stats()
//                 );
//             }
//             Err(e) => {
//                 warn!("Error reading from stream: {:?}", e);
//             }
//         }
//     }

//     // Note: In a production environment, you should implement proper cleanup
//     // by calling stream.close() when the application is terminated.
//     // For example:
//     //
//     // tokio::select! {
//     //     _ = tokio::signal::ctrl_c() => {
//     //         info!("Received shutdown signal");
//     //         stream.close().await?;
//     //     }
//     //     result = stream.read() => {
//     //         // Process result
//     //     }
//     // }
// }
