use chainlink_data_streams_report::{
    feed_id::ID,
    // report::{decode_full_report, v3::ReportDataV3},
    report::{decode_full_report, v9::ReportDataV9},
};
use chainlink_data_streams_sdk::{config::Config, stream::Stream};
use std::{sync::Arc, time::Duration};
use tokio::{task::JoinHandle, time::sleep};
use tracing::{debug, error, info};

use crate::{app_config::AppConfig, transmitter::transmitter::Transmitter};

pub async fn run(
    app_config: &AppConfig,
    transmitter: Transmitter,
) -> Result<JoinHandle<()>, anyhow::Error> {
    let mut last_verified_timestamp = 0;

    // Initialize the configuration
    let config = Config::new(
        app_config.chainlink_api_key.clone(),
        app_config.chainlink_api_secret.clone(),
        app_config.chainlink_feed_url.clone(),
        app_config.chainlink_feed_url_ws.clone(),
    )
    .build()?;

    let transmitter = Arc::new(transmitter);
    let feed_id = app_config.feed_id.clone();
    let join_handle = tokio::spawn(async move {
        let transmitter = transmitter.clone();
        // loop to reconnect, if the stream is closed
        loop {
            let feed_ids = vec![ID::from_hex_str(&feed_id).expect("Invalid feed ID")];
            let mut stream = match Stream::new(&config, feed_ids).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Error creating stream: {}", e);
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            if let Err(e) = stream.listen().await {
                error!("Error listening to stream: {}", e);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            info!("WebSocket connection established. Listening for reports...");

            while let Ok(response) = stream.read().await {
                debug!("Raw report data: {:?}", response.report);

                // Decode the report
                let Ok(full_report) = hex::decode(&response.report.full_report[2..]) else {
                    error!("Error decoding report hex");
                    continue;
                };
                let Ok((_report_context, report_blob)) = decode_full_report(&full_report) else {
                    error!("Error decoding full report");
                    continue;
                };
                let Ok(report_data) = ReportDataV9::decode(&report_blob) else {
                    error!("Error decoding report into ReportDataV9");
                    continue;
                };

                // Print decoded report details
                debug!("Stream ID: {}", response.report.feed_id.to_hex_string());
                debug!("Valid from timestamp: {}", report_data.valid_from_timestamp);
                debug!("report_data: {:#?}", report_data);
                debug!("response.report: {:#?}", response.report);
                debug!("Stream Stats: {:#?}", stream.get_stats());

                sleep(Duration::from_secs(10)).await;
                // FIXME: This should be changed to verify if the report is not same as on-chain
                // data
                if response.report.valid_from_timestamp > last_verified_timestamp + 30 {
                    info!("Verifying report...");
                    let tx = match transmitter.verify(&response.report.full_report).await {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Error verifying report: {:?}", e);
                            break;
                        }
                    };
                    info!("Signature: {}", tx);
                    last_verified_timestamp = response.report.valid_from_timestamp;
                }
            }
            error!("Stream closed, reconnecting...");
            sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(join_handle)
}
