use chainlink_data_streams_report::{
    feed_id::ID,
    report::{decode_full_report, v3::ReportDataV3, Report},
};
use chainlink_data_streams_sdk::{client::Client, config::Config};
use tracing::{debug, error};

use crate::app_config::AppConfig;
use crate::transmitter::transmitter::Transmitter;

// This function need to be called in a loop
pub async fn run(
    app_config: &AppConfig,
    transmitter: Transmitter,
) -> Result<Report, anyhow::Error> {
    let config = Config::new(
        app_config.chainlink_api_key.clone(),
        app_config.chainlink_api_secret.clone(),
        app_config.chainlink_feed_url.clone(),
        app_config.chainlink_feed_url_ws.clone(),
    )
    .build()?;

    let client = Client::new(config)?;
    let feed_id = ID::from_hex_str(&app_config.feed_id)?;

    let response = client.get_latest_report(feed_id).await?;

    debug!("Raw report data: {:?}", response.report);

    let full_report = hex::decode(&response.report.full_report[2..])?;
    let (_report_context, report_blob) = decode_full_report(&full_report)?;
    let report_data = ReportDataV3::decode(&report_blob)?;

    debug!("Decoded Report for Stream ID {}:", app_config.feed_id);
    debug!("Report.report: {:#?}", response.report);
    debug!("report_data: {:#?}", report_data);

    debug!("🌟 Verifying report...");
    let Ok(tx) = transmitter.verify(&response.report.full_report).await else {
        error!("Error verifying report");
        return Err(anyhow::anyhow!("Error verifying report"));
    };
    debug!("🌟 🌟 Signature: {}", tx);

    Ok(response.report)
}
