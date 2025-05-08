use std::path::PathBuf;

pub struct Config {
    pub wallet_path: PathBuf,
}

impl Config {
    pub fn new() -> Self {
        Self {
            wallet_path: PathBuf::from("../.secrets/fundingWallet.json"),
        }
    }
}
