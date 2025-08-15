use std::collections::HashMap;

use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct AppConfig {
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    pub signer_private_key: String,
    #[serde(default = "default_feed_id")]
    pub feed_id: String,
    #[serde(default = "default_u_address")]
    pub u_address: String,

    #[serde(default = "default_program_id")]
    pub program_id: String,

    #[serde(default = "default_chainlink_verifier_program_id")]
    pub chainlink_verifier_program_id: String,

    #[serde(default = "default_access_controller_program_id")]
    pub access_controller_program_id: String,
    #[serde(default = "default_access_controller_data_account")]
    pub access_controller_data_account: String,

    #[serde(default = "default_chainlink_feed_url")]
    pub chainlink_feed_url: String,
    #[serde(default = "default_chainlink_feed_url_ws")]
    pub chainlink_feed_url_ws: String,
    #[serde(default = "default_chainlink_api_key")]
    pub chainlink_api_key: String,
    pub chainlink_api_secret: String,
}

fn default_access_controller_data_account() -> String {
    "2k3DsgwBoqrnvXKVvd7jX7aptNxdcRBdcd5HkYsGgbrb".to_string()
}

fn default_chainlink_api_key() -> String {
    "test-key".to_string()
}

fn default_chainlink_feed_url() -> String {
    "https://api.testnet-dataengine.chain.link".to_string()
}

fn default_chainlink_feed_url_ws() -> String {
    "wss://ws.testnet-dataengine.chain.link".to_string()
}

fn default_program_id() -> String {
    proof_of_reserves::ID.to_string()
}

fn default_chainlink_verifier_program_id() -> String {
    "Gt9S41PtjR58CbG9JhJ3J6vxesqrNAswbWYbLNTMZA3c".to_string()
}

fn default_access_controller_program_id() -> String {
    "2k3DsgwBoqrnvXKVvd7jX7aptNxdcRBdcd5HkYsGgbrb".to_string()
}

fn default_rpc_url() -> String {
    "https://api.devnet.solana.com".to_string()
}

fn default_feed_id() -> String {
    "0x0009de5ffad036d889d1bef8f402ee67370b1fbdfd491d07bf0a8666b031552a".to_string()
}

fn default_u_address() -> String {
    "".to_string()
}

impl AppConfig {
    pub async fn new() -> Self {
        dotenvy::dotenv().ok();

        if let Some(secret_name) = std::env::var("SECRET_NAME").ok() {
            // Inject secret value from AWS Secrets Manager to ENV
            let secrets_manager_client = SecretsManagerClient::new(
                &aws_config::load_defaults(BehaviorVersion::latest()).await,
            );
            let json = secrets_manager_client
                .get_secret_value()
                .secret_id(secret_name)
                .send()
                .await
                .expect("Failed to get secret value")
                .secret_string()
                .expect("Failed to get secret string value")
                .to_string();

            serde_json::from_str::<HashMap<String, String>>(&json)
                .expect("Failed to parse secret value as JSON")
                .into_iter()
                .for_each(|(key, value)| {
                    // Set ENV if not set, allow .env override
                    if std::env::var(&key).is_err() {
                        std::env::set_var(key, value);
                    }
                });
        }

        let config = config::Config::builder()
            .add_source(config::Environment::default().try_parsing(true))
            .build()
            .unwrap();

        let app_config = config.try_deserialize::<AppConfig>().unwrap();

        app_config
    }
}
