use std::sync::Arc;

use anchor_client::solana_sdk::compute_budget::ComputeBudgetInstruction;
use anchor_client::solana_sdk::signature::Signature;
use anchor_client::Cluster;
use anchor_client::{solana_sdk::signature::Keypair, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};

use proof_of_reserves;

use snap::raw::Encoder;
use tracing::debug;

use crate::utils::proof_of_reserves_loader::load_proof_of_reserves;

// Report snapsho for test
pub const DEFAULT_HEX_STRING: &str = "0x00090d9e8d96765a0c49e03a6ae05c82e8f8de70cf179baa632f18313e54bd69000000000000000000000000000000000000000000000000000000000177c3ea000000000000000000000000000000000000000000000000000000030000000100000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400009fffb1e3bd8e3948987ceb484b7e0153ddcfaf6c22290f4240616891c14c30000000000000000000000000000000000000000000000000000000068a4d3b50000000000000000000000000000000000000000000000000000000068a4d3b5000000000000000000000000000000000000000000000000000045fe79dc698d000000000000000000000000000000000000000000000000002f81a8183c3a710000000000000000000000000000000000000000000000000000000068cc60b5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000198bfa08ef900000000000000000000000000000000000000000000001b1ae4d6e2ef50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002104dcc2d1654108de2c4395fcacf0c24a3d69c6d15e5714d9208a5c4cd8f6edb36288b7e25db0057cac014c76e77ee27e386cc1aa7a6f99249bb90ab390e800d00000000000000000000000000000000000000000000000000000000000000024b2faacffaa503b333432bd79df9f8b9aa4188d788346d6cb3d15f3f819b6b571b9c0c11f6c3767e398275d32f522628aea8184f64d5752b7cafa13ddb11fc4f";

pub struct Transmitter {
    pub program: Program<Arc<Keypair>>,
    pub program_id: Pubkey,
    pub u_address: Pubkey,
    pub chainlink_verifier_program_id: Pubkey,
    pub access_controller_program_id: Pubkey,
    pub access_controller_data_account: Pubkey,
}

impl Transmitter {
    pub fn new(
        cluster: Cluster,
        signer: Arc<Keypair>,
        program_id: Pubkey,
        u_address: Pubkey,
        chainlink_verifier_program_id: Pubkey,
        access_controller_program_id: Pubkey,
        access_controller_data_account: Pubkey,
    ) -> Result<Self> {
        let program = load_proof_of_reserves(program_id, cluster, signer)?;

        Ok(Self {
            program,
            program_id,
            u_address,
            chainlink_verifier_program_id,
            access_controller_program_id,
            access_controller_data_account,
        })
    }

    pub async fn get_tnf_last_updated_at(&self) -> u64 {
        let reserves_account = Pubkey::find_program_address(
            &[b"reserves", self.u_address.as_ref()],
            &self.program.id(),
        )
        .0;
        self.program
            .account::<proof_of_reserves::Reserves>(reserves_account)
            .await
            .unwrap()
            .tnf_last_updated_at
    }

    pub fn parse_and_compress_hex_report(&self, hex_string: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let clean_hex = hex_string.strip_prefix("0x").unwrap_or(hex_string);

        if clean_hex.len() % 2 != 0 {
            anyhow::bail!("Hex string has invalid length");
        }

        let raw_bytes: Vec<u8> = (0..clean_hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&clean_hex[i..i + 2], 16).with_context(|| {
                    format!("Invalid hex at position {}: {}", i, &clean_hex[i..i + 2])
                })
            })
            .collect::<Result<_>>()?;

        // Compress using Snappy
        let compressed = Encoder::new()
            .compress_vec(&raw_bytes)
            .context("Snappy compression failed")?;

        let feed_id = raw_bytes[0..32].to_vec();

        Ok((compressed, feed_id))
    }

    pub async fn verify(&self, full_report: &str, tnf_last_updated_at: u64) -> Result<Signature> {
        let (compressed_report, feed_id) = self.parse_and_compress_hex_report(full_report)?;

        let verifier_account =
            Pubkey::find_program_address(&[b"verifier"], &self.chainlink_verifier_program_id).0;

        let config_account =
            Pubkey::find_program_address(&[&feed_id], &self.chainlink_verifier_program_id).0;

        let compressed_proof_account = Pubkey::find_program_address(
            &[b"proof_v4", self.u_address.as_ref()],
            &self.program.id(),
        )
        .0;

        let reserves_account = Pubkey::find_program_address(
            &[b"reserves", self.u_address.as_ref()],
            &self.program.id(),
        )
        .0;

        let user = self.program.payer();

        let config_pda = Pubkey::find_program_address(
            &[&"config_pda".as_bytes(), self.u_address.as_ref()],
            &self.program.id(),
        )
        .0;

        let account = proof_of_reserves::accounts::Verify {
            verifier_account,
            access_controller: self.access_controller_data_account,
            user,
            config_pda,
            u: self.u_address,
            verifier_config_account: config_account,
            verifier_program_id: self.chainlink_verifier_program_id,
            compressed_proof: compressed_proof_account,
            reserves_pda: reserves_account,
            system_program: anchor_client::solana_sdk::system_program::ID,
        };

        debug!("account.verify_account: {:?}", account.verifier_account);
        debug!("account.access_controller: {:?}", account.access_controller);
        debug!("account.user: {:?}", account.user);
        debug!("account.config_pda: {:?}", account.config_pda);
        debug!("account.u: {:?}", account.u);
        debug!(
            "account.verifier_config_account: {:?}",
            account.verifier_config_account
        );
        debug!(
            "account.verifier_program_id: {:?}",
            account.verifier_program_id
        );
        debug!("account.compressed_proof: {:?}", account.compressed_proof);
        debug!("account.reserves_pda: {:?}", account.reserves_pda);
        debug!("account.system_program: {:?}", account.system_program);

        let verify_ix = self
            .program
            .request()
            .accounts(account)
            .args(proof_of_reserves::instruction::Verify {
                signed_report: compressed_report,
                tnf_last_updated_at,
            })
            .instructions()?
            .remove(0);

        let tx = self
            .program
            .request()
            .instruction(ComputeBudgetInstruction::set_compute_unit_limit(500_000))
            .instruction(verify_ix)
            .send()
            .await?;

        let compressed_proof_account: proof_of_reserves::CompressedProof =
            self.program.account(compressed_proof_account).await?;

        let (proof_state, _) =
            proof_of_reserves::ProofState::decode(&compressed_proof_account.compressed_proof)
                .unwrap();

        let reserves_account: proof_of_reserves::Reserves =
            self.program.account(reserves_account).await?;

        debug!("Proof State: {:#?}", proof_state);
        debug!("Reserves Account: {:#?}", reserves_account);

        Ok(tx)
    }
}
