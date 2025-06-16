use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anchor_client::solana_sdk::native_token::LAMPORTS_PER_SOL;
use anchor_client::solana_sdk::signature::Signature;
use anchor_client::Cluster;
use anchor_client::{solana_sdk::signature::Keypair, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};

use proof_of_reserves;

use snap::raw::Encoder;

use crate::utils::proof_of_reserves_loader::load_proof_of_reserves;

pub const DEFAULT_HEX_STRING: &str = "0x00064f2cd1be62b7496ad4897b984db99243e0921906f66ded15149d993ef42c000000000000000000000000000000000000000000000000000000000103c90c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200003684ea93c43ed7bd00ab3bb189bb62f880436589f1ca58b599cd97d6007fb0000000000000000000000000000000000000000000000000000000067570fa40000000000000000000000000000000000000000000000000000000067570fa400000000000000000000000000000000000000000000000000004c6ac85bf854000000000000000000000000000000000000000000000000002e1bf13b772a9c0000000000000000000000000000000000000000000000000000000067586124000000000000000000000000000000000000000000000000002bb4cf7662949c000000000000000000000000000000000000000000000000002bae04e2661000000000000000000000000000000000000000000000000000002bb6a26c3fbeb80000000000000000000000000000000000000000000000000000000000000002af5e1b45dd8c84b12b4b58651ff4173ad7ca3f5d7f5374f077f71cce020fca787124749ce727634833d6ca67724fd912535c5da0f42fa525f46942492458f2c2000000000000000000000000000000000000000000000000000000000000000204e0bfa6e82373ae7dff01a305b72f1debe0b1f942a3af01bad18e0dc78a599f10bc40c2474b4059d43a591b75bdfdd80aafeffddfd66d0395cca2fdeba1673d";

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

    pub async fn verify(&self, full_report: &str) -> Result<Signature> {
        let (compressed_report, feed_id) = self.parse_and_compress_hex_report(full_report)?;
        let feed_id_array: [u8; 32] = feed_id
            .clone()
            .try_into()
            .expect("feed_id must be 32 bytes");
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let proof_state_from_tnf = proof_of_reserves::ProofState {
            name: "Uranium Proof of Reserves".to_string(),
            total_reserves: 13 * 10u64.pow(6) * LAMPORTS_PER_SOL,
            total_token: 12 * 10u64.pow(6) * LAMPORTS_PER_SOL,
            ripcord: false,
            ripcord_details: vec![],
            timestamp: time_now as i64,
        };

        let compressed_proof = proof_of_reserves::CompressedProof {
            compressed_proof: proof_state_from_tnf.encode(&feed_id_array),
        };

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
            reserves: reserves_account,
            system_program: anchor_client::solana_sdk::system_program::ID,
        };

        println!("account.verify_account: {:?}", account.verifier_account);
        println!("account.access_controller: {:?}", account.access_controller);
        println!("account.user: {:?}", account.user);
        println!("account.config_pda: {:?}", account.config_pda);
        println!("account.u: {:?}", account.u);
        println!(
            "account.verifier_config_account: {:?}",
            account.verifier_config_account
        );
        println!(
            "account.verifier_program_id: {:?}",
            account.verifier_program_id
        );
        println!("account.compressed_proof: {:?}", account.compressed_proof);
        println!("account.reserves: {:?}", account.reserves);
        println!("account.system_program: {:?}", account.system_program);

        let verify_ix = self
            .program
            .request()
            .accounts(account)
            .args(proof_of_reserves::instruction::Verify {
                signed_report: compressed_report,
                compressed_proof: compressed_proof.compressed_proof,
            })
            .instructions()?
            .remove(0);

        let tx = self.program.request().instruction(verify_ix).send().await?;

        let compressed_proof_account: proof_of_reserves::CompressedProof =
            self.program.account(compressed_proof_account).await?;

        let (proof_state, _) =
            proof_of_reserves::ProofState::decode(&compressed_proof_account.compressed_proof)
                .unwrap();

        let reserves_account: proof_of_reserves::Reserves =
            self.program.account(reserves_account).await?;

        println!("Proof State: {:#?}", proof_state);
        println!("Reserves Account: {:#?}", reserves_account);

        Ok(tx)
    }
}
