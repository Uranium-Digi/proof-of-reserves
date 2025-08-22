mod modes;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::Cluster;
use anchor_lang::prelude::Pubkey;
use app_config::AppConfig;
use modes::directapi::DirectApiService;

use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{info, warn};
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
    let transmitter = Arc::new(Transmitter::new(
        cluster,
        Arc::new(signer),
        proof_of_reserves_program_id,
        u_address,
        chainlink_verifier_program_id,
        access_controller_program_id,
        access_controller_data_account,
    )?);

    let direct_api_service =
        Arc::new(DirectApiService::new(Arc::new(app_config), transmitter.clone()).await);

    let mut sched = JobScheduler::new().await?;
    sched
        .add(Job::new_async("0 */5 * * * *", move |_uuid, _l| {
            let direct_api_service = direct_api_service.clone();
            Box::pin(async move {
                info!("🌟 Verifying report...");
                let result = direct_api_service.run().await;
                match result {
                    Ok(Some((report, tx))) => {
                        info!("🌟 🌟 Report: {:?}, Signature: {}", report, tx)
                    }
                    Ok(None) => info!("Report not updated"),
                    Err(e) => warn!("Error verifying report: {:?}", e),
                }
            })
        })?)
        .await?;

    sched.start().await?;

    // Graceful shutdown on Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("Shutting down scheduler...");
    sched.shutdown().await?;

    Ok(())
}
