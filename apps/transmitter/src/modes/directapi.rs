use std::sync::Arc;

use anchor_client::solana_sdk::signature::Signature;
use chainlink_data_streams_report::{
    feed_id::ID,
    report::{decode_full_report, v9::ReportDataV9, Report},
};
use chainlink_data_streams_sdk::{client::Client, config::Config};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::Deserialize;
use tracing::{debug, error};

use crate::app_config::AppConfig;
use crate::transmitter::transmitter::Transmitter;

pub struct DirectApiService {
    app_config: Arc<AppConfig>,
    transmitter: Arc<Transmitter>,
}

#[allow(dead_code)]
#[serde_with::serde_as]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TnfResponse {
    pub name: Option<String>,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub total_reserve: Decimal,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub total_token: Decimal,
    pub ripcord: bool,
    pub ripcord_details: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

impl DirectApiService {
    pub async fn new(app_config: Arc<AppConfig>, transmitter: Arc<Transmitter>) -> Self {
        let last_tnf_updated_at = transmitter.get_tnf_last_updated_at().await;
        debug!("last_tnf_updated_at: {last_tnf_updated_at}");
        Self {
            app_config,
            transmitter,
        }
    }

    pub async fn run(&self) -> Result<Option<(Report, Signature)>, anyhow::Error> {
        let client = reqwest::Client::new();
        let tnf_res = client
            .get(self.app_config.tnf_api_endpoint.clone())
            .header("apikey", self.app_config.tnf_api_key.clone())
            .header("Accept", "application/json")
            .header("User-Agent", "Uranium transmitter")
            .send()
            .await?
            .json::<TnfResponse>()
            .await?;

        let last_tnf_updated_at = self.transmitter.get_tnf_last_updated_at().await;

        if tnf_res.timestamp.timestamp() as u64 <= last_tnf_updated_at {
            // No new report
            return Ok(None);
        }

        let config = Config::new(
            self.app_config.chainlink_api_key.clone(),
            self.app_config.chainlink_api_secret.clone(),
            self.app_config.chainlink_feed_url.clone(),
            self.app_config.chainlink_feed_url_ws.clone(),
        )
        .build()?;

        let client = Client::new(config)?;
        let feed_id = ID::from_hex_str(&self.app_config.feed_id)?;

        let response = client.get_latest_report(feed_id).await?;

        debug!("Raw report data: {:?}", response.report);

        let full_report = hex::decode(&response.report.full_report[2..])?;
        let (_report_context, report_blob) = decode_full_report(&full_report)?;
        let report_data = ReportDataV9::decode(&report_blob)?;

        debug!("Decoded Report for Stream ID {}:", self.app_config.feed_id);
        debug!("Report.report: {:#?}", response.report);
        debug!("report_data: {:#?}", report_data);

        debug!("🌟 Verifying report...");
        let Ok(tx) = self
            .transmitter
            .verify(
                &response.report.full_report,
                tnf_res.timestamp.timestamp() as u64,
            )
            .await
        else {
            error!("Error verifying report");
            return Err(anyhow::anyhow!("Error verifying report"));
        };

        Ok(Some((response.report, tx)))
    }
}
