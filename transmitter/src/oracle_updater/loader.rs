use std::env;

use anchor_client::{
    Client, Cluster, Program,
    solana_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        signature::{Keypair, read_keypair_file},
        signer::Signer,
    },
};
use anchor_lang::prelude::Pubkey;
use anyhow::Result;
use serde_json;
use std::rc::Rc;

pub struct OracleUpdaterProgram {
    pub program: Program<Rc<Keypair>>,
    pub program_id: Pubkey,
}

use crate::wallet_loader;

impl OracleUpdaterProgram {
    pub fn new(commitment: CommitmentConfig) -> Result<Self> {
        let rpc_url =
            env::var("RPC_URL").map_err(|_| anyhow::anyhow!("RPC_URL env variable is not set"))?;

        let wallet = wallet_loader::load_funding_wallet()?;

        let provider = Client::new_with_options(
            Cluster::Custom(rpc_url.to_string(), rpc_url.to_string()),
            wallet,
            commitment,
        );

        // Load program ID from the oracle-updater target directory
        let keypair =
            read_keypair_file("../oracle-updater/target/deploy/oracle_updater-keypair.json")
                .map_err(|e| anyhow::anyhow!("Failed to read keypair file: {}", e))?;
        let program_id = keypair.pubkey();
        println!("program_id: {}", program_id);
        let program = provider.program(program_id)?;

        Ok(Self {
            program,
            program_id,
        })
    }

    // pub fn verify(
    //     &self,
    //     verifier_account: Pubkey,
    //     access_controller: Pubkey,
    //     user: Pubkey,
    //     config_account: Pubkey,
    //     verifier_program_id: Pubkey,
    //     signed_report: Vec<u8>,
    // ) -> Result<()> {
    //     let verify_ix = self
    //         .program
    //         .request()
    //         .accounts(oracle_updater::ExampleProgramContext {
    //             verifier_account,
    //             access_controller,
    //             user,
    //             config_account,
    //             verifier_program_id,
    //         })
    //         .args(signed_report)
    //         .instructions()?
    //         .remove(0);

    //     self.program.request().instruction(verify_ix).send()?;

    //     Ok(())
    // }
}
