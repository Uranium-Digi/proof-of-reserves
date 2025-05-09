use chainlink_data_streams_report::feed_id::ID;
use chainlink_data_streams_report::report::{Report, decode_full_report, v3::ReportDataV3};
use chainlink_data_streams_sdk::client::Client;
use chainlink_data_streams_sdk::config::Config;
use dotenv::dotenv;
use std::env;
use std::error::Error;

// https://docs.chain.link/data-streams/tutorials/streams-direct/streams-direct-api-rust

const DEFAULT_FEED_ID: &str = "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

pub async fn run() -> Result<(Report), Box<dyn Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    // Get API credentials from environment variables
    let api_key = env::var("API_KEY").expect("API_KEY must be set");
    let api_secret = env::var("API_SECRET").expect("API_SECRET must be set");

    let feed_id_input = DEFAULT_FEED_ID;

    println!("KEY: {}", api_key);

    // Initialize the config
    let config = Config::new(
        api_key,
        api_secret,
        "https://api.testnet-dataengine.chain.link".to_string(),
        "wss://api.testnet-dataengine.chain.link/ws".to_string(),
    )
    .build()?;

    // Initialize the client
    let client = Client::new(config)?;
    // Parse the feed ID
    let feed_id = ID::from_hex_str(feed_id_input)?;

    // Fetch the latest report
    let response = client.get_latest_report(feed_id).await?;
    println!("\nRaw report data: {:?}\n", response.report);
    // decode the report
    let full_report = hex::decode(&response.report.full_report[2..])?;
    let (_report_context, report_blob) = decode_full_report(&full_report)?;
    let report_data = ReportDataV3::decode(&report_blob)?;

    // Print decoded report details
    println!("\nDecoded Report for Stream ID {}:", feed_id_input);
    println!("------------------------------------------");
    println!(
        "Observations Timestamp: {}",
        response.report.observations_timestamp
    );
    println!("Benchmark Price       : {}", report_data.benchmark_price);
    println!("Bid                   : {}", report_data.bid);
    println!("Ask                   : {}", report_data.ask);
    println!(
        "Valid From Timestamp  : {}",
        response.report.valid_from_timestamp
    );
    println!("Expires At            : {}", report_data.expires_at);
    println!("Link Fee              : {}", report_data.link_fee);
    println!("Native Fee            : {}", report_data.native_fee);
    println!("------------------------------------------");

    println!("report_data: {:#?}", report_data);

    println!("response.report: {:#?}", response.report);

    Ok((response.report))
}

// pub async fn run(feed_id_input: &str) -> Result<(), Box<dyn Error>> {
// pub async fn run(feed_id_input: &str) -> Result<(Report), Box<dyn Error>> {
//     // Load environment variables from .env file
//     dotenv().ok();

//     // Get feed ID from command line arguments
//     let args: Vec<String> = env::args().collect();
//     if args.len() < 2 {
//         eprintln!("Usage: cargo run [feed_id]");
//         std::process::exit(1);
//     }

//     // let feed_id_input = &args[1];

//     // Get API credentials from environemt variables
//     let api_key = env::var("API_KEY").expect("API_KEY must be set");
//     let api_secret = env::var("API_SECRET").expect("API_SECRET must be set");

//     println!("KEY: {}", api_key);

//     // Initialize the config
//     let config = Config::new(
//         api_key,
//         api_secret,
//         "https://api.testnet-dataengine.chain.link".to_string(),
//         "wss://api.testnet-dataengine.chain.link/ws".to_string(),
//     )
//     .build()?;

//     // Initialize the client
//     let client = Client::new(config)?;
//     // Parse the feed ID
//     let feed_id = ID::from_hex_str(feed_id_input)?;

//     // Fetch the latest report
//     let response = client.get_latest_report(feed_id).await?;
//     println!("\nRaw report data: {:?}\n", response.report);
//     // decode the report
//     let full_report = hex::decode(&response.report.full_report[2..])?;
//     let (_report_context, report_blob) = decode_full_report(&full_report)?;
//     let report_data = ReportDataV3::decode(&report_blob)?;

//     // Print decoded report details
//     println!("\nDecoded Report for Stream ID {}:", feed_id_input);
//     println!("------------------------------------------");
//     println!(
//         "Observations Timestamp: {}",
//         response.report.observations_timestamp
//     );
//     println!("Benchmark Price       : {}", report_data.benchmark_price);
//     println!("Bid                   : {}", report_data.bid);
//     println!("Ask                   : {}", report_data.ask);
//     println!(
//         "Valid From Timestamp  : {}",
//         response.report.valid_from_timestamp
//     );
//     println!("Expires At            : {}", report_data.expires_at);
//     println!("Link Fee              : {}", report_data.link_fee);
//     println!("Native Fee            : {}", report_data.native_fee);
//     println!("------------------------------------------");

//     println!("report_data: {:?}", report_data);
//     // println!("response: {:?}", response);
//     // Ok(())

//     // return the raw report data
//     Ok(response.report)
// }

// Direct API implementation will go here
