use anchor_lang::prelude::Pubkey;
use chainlink_data_streams_report::feed_id::ID;
// Import the v3 report schema for Crypto streams
use chainlink_data_streams_report::report::{Report, decode_full_report, v3::ReportDataV3};
use chainlink_data_streams_sdk::config::Config;
use chainlink_data_streams_sdk::stream::Stream;
use dotenv::dotenv;
use std::env;
use std::error::Error;
use std::str::FromStr;
use tracing::{info, warn};
use tracing_subscriber::fmt::time::UtcTime;

use crate::transmitter::transmitter::Transmitter;
use crate::utils::config::{DEFAULT_FEED_ID, U_ADDRESS};

// https://docs.chain.link/data-streams/tutorials/streams-direct/streams-direct-ws-rust
// #[tokio::main]

pub async fn run(transmitter: &Transmitter) -> Result<(), Box<dyn Error>> {
    let feed_id_input = DEFAULT_FEED_ID;
    let last_verified_timestamp = 0;
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize logging with UTC timestamps
    tracing_subscriber::fmt()
        .with_timer(UtcTime::rfc_3339())
        .with_max_level(tracing::Level::INFO)
        .init();

    // Get API credentials from environment variables
    let api_key = env::var("API_KEY").expect("API_KEY must be set");
    let api_secret = env::var("API_SECRET").expect("API_SECRET must be set");
    let u = Pubkey::from_str(U_ADDRESS).expect("Invalid U_ADDRESS");

    let mut feed_ids = Vec::new();
    let feed_id = ID::from_hex_str(feed_id_input)?;
    feed_ids.push(feed_id);

    // Initialize the configuration
    let config = Config::new(
        api_key,
        api_secret,
        "https://api.testnet-dataengine.chain.link".to_string(),
        "wss://ws.testnet-dataengine.chain.link".to_string(),
    )
    .build()?;

    // Create and initialize the stream
    let mut stream = Stream::new(&config, feed_ids).await?;
    stream.listen().await?;

    info!("WebSocket connection established. Listening for reports...");

    // Process incoming reports
    loop {
        match stream.read().await {
            Ok(response) => {
                info!("\nRaw report data: {:?}\n", response.report);

                // Decode the report
                let full_report = hex::decode(&response.report.full_report[2..])?;
                let (_report_context, report_blob) = decode_full_report(&full_report)?;
                let report_data = ReportDataV3::decode(&report_blob)?;

                // Print decoded report details
                info!(
                    "\n--- Report Stream ID: {} ---\n\
                     ------------------------------------------\n\
                     Observations Timestamp : {}\n\
                     Price                 : {}\n\
                     Bid                   : {}\n\
                     Ask                   : {}\n\
                     Valid From Timestamp  : {}\n\
                     Expires At           : {}\n\
                     Link Fee             : {}\n\
                     Native Fee           : {}\n\
                     ------------------------------------------",
                    response.report.feed_id.to_hex_string(),
                    response.report.observations_timestamp,
                    report_data.benchmark_price,
                    report_data.bid,
                    report_data.ask,
                    response.report.valid_from_timestamp,
                    report_data.expires_at,
                    report_data.link_fee,
                    report_data.native_fee,
                );

                // Print stream stats
                info!(
                    "\n--- Stream Stats ---\n{:#?}\n\
                     --------------------------------------------------------------------------------------------------------------------------------------------",
                    stream.get_stats()
                );

                if response.report.valid_from_timestamp > last_verified_timestamp + 30 {
                    // verify the last report every 30 seconds
                    info!("🌟 Verifying report...");
                    let tx = transmitter.verify(&response.report.full_report, None, u).await?;
                    info!("🌟 🌟 Signature: {}", tx);
                }
            }
            Err(e) => {
                warn!("Error reading from stream: {:?}", e);
            }
        }
    }

    // Note: In a production environment, you should implement proper cleanup
    // by calling stream.close() when the application is terminated.
    // For example:
    //
    // tokio::select! {
    //     _ = tokio::signal::ctrl_c() => {
    //         info!("Received shutdown signal");
    //         stream.close().await?;
    //     }
    //     result = stream.read() => {
    //         // Process result
    //     }
    // }
}

// // WebSocket implementation will go here

// pub async fn run() -> Result<(), Box<dyn Error>> {
//     let feed_id_input = DEFAULT_FEED_ID;
//     // Load environment variables from .env file
//     dotenv().ok();

//     // Initialize logging with UTC timestamps
//     tracing_subscriber::fmt()
//         .with_timer(UtcTime::rfc_3339())
//         .with_max_level(tracing::Level::INFO)
//         .init();

//     // Get API credentials from environment variables
//     let api_key = env::var("API_KEY").expect("API_KEY must be set");
//     let api_secret = env::var("API_SECRET").expect("API_SECRET must be set");

//     let mut feed_ids = Vec::new();
//     let feed_id = ID::from_hex_str(feed_id_input)?;
//     feed_ids.push(feed_id);

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

// WebSocket implementation will go here
