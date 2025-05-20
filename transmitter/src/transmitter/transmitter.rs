use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anchor_client::solana_sdk::lamports;
use anchor_client::solana_sdk::native_token::LAMPORTS_PER_SOL;
use anchor_client::solana_sdk::signature::Signature;
use anchor_client::Cluster;
use anchor_client::{solana_sdk::signature::Keypair, Program};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use oracle_updater::program::OracleUpdater;

use std::rc::Rc;

use oracle_updater;

use snap::raw::Encoder;

use crate::utils::oracle_updater_loader::{load_oracle_updater, RouteType};

pub const CHAINLINK_VERIFIER_PROGRAM_ID_DEVNET: &str =
    "Gt9S41PtjR58CbG9JhJ3J6vxesqrNAswbWYbLNTMZA3c";
pub const ACCESS_CONTROLLER: &str = "2k3DsgwBoqrnvXKVvd7jX7aptNxdcRBdcd5HkYsGgbrb";
pub const DEFAULT_HEX_STRING: &str = "0x00064f2cd1be62b7496ad4897b984db99243e0921906f66ded15149d993ef42c000000000000000000000000000000000000000000000000000000000103c90c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200003684ea93c43ed7bd00ab3bb189bb62f880436589f1ca58b599cd97d6007fb0000000000000000000000000000000000000000000000000000000067570fa40000000000000000000000000000000000000000000000000000000067570fa400000000000000000000000000000000000000000000000000004c6ac85bf854000000000000000000000000000000000000000000000000002e1bf13b772a9c0000000000000000000000000000000000000000000000000000000067586124000000000000000000000000000000000000000000000000002bb4cf7662949c000000000000000000000000000000000000000000000000002bae04e2661000000000000000000000000000000000000000000000000000002bb6a26c3fbeb80000000000000000000000000000000000000000000000000000000000000002af5e1b45dd8c84b12b4b58651ff4173ad7ca3f5d7f5374f077f71cce020fca787124749ce727634833d6ca67724fd912535c5da0f42fa525f46942492458f2c2000000000000000000000000000000000000000000000000000000000000000204e0bfa6e82373ae7dff01a305b72f1debe0b1f942a3af01bad18e0dc78a599f10bc40c2474b4059d43a591b75bdfdd80aafeffddfd66d0395cca2fdeba1673d";
pub const DEFAULT_FEED_ID: &'static str =
    "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

pub struct Transmitter {
    pub program: Program<Rc<Keypair>>,
    pub program_id: Pubkey,
}

impl Transmitter {
    pub fn new(cluster: Option<Cluster>) -> Result<Self> {
        let (program, program_id) = load_oracle_updater(cluster, RouteType::default())?;

        println!("program_id: {}", program_id);

        Ok(Self {
            program,
            program_id,
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
        let proof_state_from_tnf = oracle_updater::ProofState {
            name: "Uranium Proof of Reserves".to_string(),
            total_reserves: 13 * 10u64.pow(6) * LAMPORTS_PER_SOL,
            total_token: 12 * 10u64.pow(6) * LAMPORTS_PER_SOL,
            ripcord: false,
            ripcord_details: vec![],
            timestamp: time_now as i64,
        };

        let compressed_proof = oracle_updater::CompressedProof {
            compressed_proof: proof_state_from_tnf.encode(&feed_id_array),
        };

        println!(
            "Transmitter - verify() - build | compressed_report: {:?}",
            compressed_report
        );
        println!(
            "Transmitter - verify() - build | compressed_proof: {:?}",
            compressed_proof.compressed_proof
        );

        let verifier_program_id: Pubkey =
            Pubkey::from_str(CHAINLINK_VERIFIER_PROGRAM_ID_DEVNET).unwrap();

        let access_controller: Pubkey = Pubkey::from_str(ACCESS_CONTROLLER).unwrap();

        let (verifier_account, _) =
            Pubkey::find_program_address(&[b"verifier"], &verifier_program_id);

        let (config_account, _) = Pubkey::find_program_address(&[&feed_id], &verifier_program_id);

        // This is the PDA for ProofState (owned by oracle_updater)
        println!("program.id: {:?}", &self.program.id());

        let (compressed_proof_account, _) =
            Pubkey::find_program_address(&[b"proof_v4"], &self.program.id());
        println!("compressed_proof_account: {:?}", &compressed_proof_account);

        let (mintable_account, _) =
            Pubkey::find_program_address(&[b"mintable_account"], &self.program.id());
        println!("mintable_account: {:?}", &mintable_account);

        // Make sure this seed matches the on-chain logic
        let user = self.program.payer();

        // let proof_state = &mut ctx.accounts.proof_state;
        let verify_ix = self
            .program
            .request()
            .accounts(oracle_updater::accounts::ExampleProgramContext {
                verifier_account,
                access_controller,
                user,
                config_account,
                verifier_program_id,
                compressed_proof: compressed_proof_account,
                mintable_account,
                system_program: anchor_client::solana_sdk::system_program::ID,
            })
            .args(oracle_updater::instruction::Verify {
                signed_report: compressed_report,
                compressed_proof: compressed_proof.compressed_proof,
            })
            .instructions()?
            .remove(0);

        let tx = self.program.request().instruction(verify_ix).send().await?;

        println!("✅ Transaction successful!");
        println!("🔗 Signature: {}", tx);
        println!("\n📋 Program Logs");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("📍 Instruction: Verify");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let compressed_proof_account: oracle_updater::CompressedProof =
            self.program.account(compressed_proof_account).await?;

        let (proof_state, _) =
            oracle_updater::ProofState::decode(&compressed_proof_account.compressed_proof).unwrap();

        println!("🧻 Proof State:");
        println!("  Name: {}", proof_state.name);
        println!("  Total Reserves: {}", proof_state.total_reserves);
        println!("  Total Token: {}", proof_state.total_token);
        println!("  Ripcord: {}", proof_state.ripcord);
        println!("  Ripcord Details: {:?}", proof_state.ripcord_details);
        println!("  Timestamp: {}", proof_state.timestamp);

        let mintable_account: oracle_updater::Mintable =
            self.program.account(mintable_account).await?;

        println!("🔶  Mintable Account:");
        println!("    Mintable: {}", mintable_account.mintable);

        Ok(tx)
    }
}
