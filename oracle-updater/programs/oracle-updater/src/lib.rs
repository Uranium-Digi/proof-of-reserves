use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::{get_return_data, invoke},
    pubkey::Pubkey,
};
use chainlink_data_streams_report::report::v3::ReportDataV3;
use chainlink_solana_data_streams::VerifierInstructions;

use hex;

// https://docs.chain.link/data-streams/tutorials/streams-direct/solana-onchain-report-verification
declare_id!("8y6CXiQsLVXa98ASAeC9oMmo9GV7n7Z2mCwUJysYjUYs");

#[program]
pub mod oracle_updater {
    use super::*;

    /// Verifies a Data Streams report using Cross-Program Invocation to the Verifier program
    /// Returns the decoded report data if verification succeeds

    pub fn verify(
        ctx: Context<ExampleProgramContext>,
        signed_report: Vec<u8>,
        proof_state_from_tnf: ProofState,
        feed_id: [u8; 32],
        // can_mint_amount: u64,
        // can_burn_amount: u64,
        // total_reserves: u64,
    ) -> Result<()> {
        let program_id = ctx.accounts.verifier_program_id.key();
        let verifier_account = ctx.accounts.verifier_account.key();
        let access_controller = ctx.accounts.access_controller.key();
        let user = ctx.accounts.user.key();
        let config_account = ctx.accounts.config_account.key();

        // Create verification instruction
        let chainlink_ix: Instruction = VerifierInstructions::verify(
            &program_id,
            &verifier_account,
            &access_controller,
            &user,
            &config_account,
            signed_report,
        );

        // Invoke the Verifier program
        invoke(
            &chainlink_ix,
            &[
                ctx.accounts.verifier_account.to_account_info(),
                ctx.accounts.access_controller.to_account_info(),
                ctx.accounts.user.to_account_info(),
                ctx.accounts.config_account.to_account_info(),
            ],
        )?;

        // Decode and log the verified report data
        if let Some((_program_id, return_data)) = get_return_data() {
            msg!("Report data found!");
            let report = ReportDataV3::decode(&return_data)
                .map_err(|_| error!(CustomError::InvalidReportData))?;

            // Report structure format:
            // {
            //   "name": "Display Name",
            //   "totalReserve": "1000000.00",
            //   "totalToken": "900000.00",
            //   "ripcord": false,      // Indicates if system should prevent onchain updates
            //   "ripcordDetails": [],  // Additional details for ripcord state
            //   "timestamp": "2024-08-02T12:00:00.000Z"
            // }
            
            let hex_proof = proof_state_from_tnf.convert_to_hex_string_with_feed_id(&feed_id);
            let hex_proof_string= &mut ctx.accounts.hex_proof_state;
            hex_proof_string.hex_string = hex_proof.clone();
            // The ProofState struct below mirrors this structure
            let proof_state = &mut ctx.accounts.hex_proof_state;

    
            // proof_state.name = "Proof of Reserves".to_string();
            // proof_state.total_reserves = proof_state_from_tnf.total_reserves;
            // proof_state.total_token = proof_state_from_tnf.total_token;
            // proof_state.ripcord = proof_state_from_tnf.ripcord;
            // proof_state.ripcord_details = proof_state_from_tnf.ripcord_details;
            // proof_state.timestamp = report.observations_timestamp as i64;

            // Log report fields
            msg!("FeedId: {}", report.feed_id);
            msg!("Valid from timestamp: {}", report.valid_from_timestamp);
            msg!("Observations Timestamp: {}", report.observations_timestamp);
            msg!("Native Fee: {}", report.native_fee);
            msg!("Link Fee: {}", report.link_fee);
            msg!("Expires At: {}", report.expires_at);
            msg!("Benchmark Price: {}", report.benchmark_price);
            msg!("Bid: {}", report.bid);
            msg!("Ask: {}", report.ask);

            // // log the proof state
            msg!("Proof State: {:?}", proof_state);
            msg!("hex_proof {:?}", hex_proof.clone());
        } else {
            msg!("No report data found!");
            return Err(error!(CustomError::NoReportData));
        }
        Ok(())
    }
    // pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    //     msg!("Greetings from: {:?}", ctx.program_id);
    //     Ok(())
    // }
}

#[derive(Accounts)]
pub struct Initialize {}

#[error_code]
pub enum CustomError {
    #[msg("No valid report data found")]
    NoReportData,
    #[msg("Invalid report data format")]
    InvalidReportData,
    #[msg("Invalid hex string")]
    InvalidHexString,
    #[msg("Invalid UTF-8 string")]
    InvalidUtf8String,
}

#[derive(Accounts)]
pub struct ExampleProgramContext<'info> {
    /// The Verifier Account stores the DON's public keys and other verification parameters.
    /// This account must match the PDA derived from the verifier program.
    /// CHECK: The account is validated by the verifier program.
    pub verifier_account: AccountInfo<'info>,
    /// The Access Controller Account
    /// /// CHECK: The account strudcture is validated by the verifier program.
    pub access_controller: AccountInfo<'info>,
    /// The account that signs the transaction.

    #[account(mut)]
    pub user: Signer<'info>,
    // pub user: Signer<'info>,
    /// The Config Account is a PDA derived from a signed report
    /// CHECK: the account is validated by the verifier program.
    pub config_account: AccountInfo<'info>,
    /// The Verifier Program ID specifies the target Chainlink Data Streams Verifier program
    /// CHECK: The program ID is validated by the verifier program.
    pub verifier_program_id: AccountInfo<'info>,
    /// PDA that stores the last verified report
    #[account(
        init_if_needed,
        seeds=[b"proof"],
        bump, payer = user,        
        space = 8 + std::mem::size_of::<HexProof>()
    )]
    pub hex_proof_state: Account<'info, HexProof>,
    pub system_program: Program<'info, System>,
}

// The report structure from the TNF should look like this:
// {
//     "name": "Display Name",
//     "totalReserve": "1000000.00",
//     "totalToken": "900000.00",
//     "ripcord": false,  // fail - system records - tells the oracle to nnot a make an onchain update
//     "ripcordDetails": [],
//     "timestamp": "2024-08-02T12:00:00.000Z"
//   }
// Therefore let us emulate its structure in the ProofState struct

#[account]
#[derive(Debug)]
pub struct HexProof {
    // Store as raw bytes intead of 
    pub hex_string: String,
}



#[account]
#[derive(Debug)]
pub struct ProofState {
    pub name: String,
    pub total_reserves: u64,
    pub total_token: u64,
    pub ripcord: bool,
    pub ripcord_details: Vec<String>,
    pub timestamp: i64,
}


impl ProofState {

    pub const DEFAULT_FEED_ID: &'static str = "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

    pub fn convert_to_hex_string_with_feed_id(&self, feed_id: &[u8; 32]) -> String {
        let mut bytes = Vec::new();
    
        // 👇 First 32 bytes must be feed_id
        bytes.extend_from_slice(feed_id);
    
        // Now serialize the rest
        let name_bytes = self.name.as_bytes();
        bytes.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name_bytes);
    
        bytes.extend_from_slice(&self.total_reserves.to_le_bytes());
        bytes.extend_from_slice(&self.total_token.to_le_bytes());
    
        bytes.push(self.ripcord as u8);
    
        bytes.extend_from_slice(&(self.ripcord_details.len() as u32).to_le_bytes());
        for detail in &self.ripcord_details {
            let detail_bytes = detail.as_bytes();
            bytes.extend_from_slice(&(detail_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(detail_bytes);
        }
    
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
    
        hex::encode(bytes)
    }
    
    
    pub fn convert_to_hex_string(&self) -> String {
        let mut bytes = Vec::new();

        // Serialize name: length + utf-8 bytes
        let name_bytes = self.name.as_bytes();
        bytes.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name_bytes);

        // total_reserves and total_token: u64
        bytes.extend_from_slice(&self.total_reserves.to_le_bytes());
        bytes.extend_from_slice(&self.total_token.to_le_bytes());

        // ripcord: bool as u8
        bytes.push(self.ripcord as u8);

        // ripcord_details: Vec<String>
        bytes.extend_from_slice(&(self.ripcord_details.len() as u32).to_le_bytes());
        for detail in &self.ripcord_details {
            let detail_bytes = detail.as_bytes();
            bytes.extend_from_slice(&(detail_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(detail_bytes);
        }

        // timestamp: i64
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        hex::encode(bytes)
    }

    pub fn decode_from_hex_string(hex: &str) -> Result<(Self, [u8; 32])> {
        let clean = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(clean).map_err(|_| error!(CustomError::InvalidHexString))?;

        if bytes.len() < 32 {
            return Err(error!(CustomError::InvalidHexString));
        }

        let feed_id: [u8; 32] = bytes[0..32].try_into().unwrap();
        let mut offset = 32;

        // name
        let name_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let name = String::from_utf8(bytes[offset..offset + name_len].to_vec())
            .map_err(|_| error!(CustomError::InvalidUtf8String))?;
        offset += name_len;

        let total_reserves = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let total_token = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let ripcord = bytes[offset] != 0;
        offset += 1;

        let num_details = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut ripcord_details = Vec::new();
        for _ in 0..num_details {
            let detail_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let detail = String::from_utf8(bytes[offset..offset + detail_len].to_vec())
                .map_err(|_| error!(CustomError::InvalidUtf8String))?;
            offset += detail_len;
            ripcord_details.push(detail);
        }

        let timestamp = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());

        Ok((
            ProofState {
                name,
                total_reserves,
                total_token,
                ripcord,
                ripcord_details,
                timestamp,
            },
            feed_id,
        ))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_proof_state_encoding_decoding() {
        let feed_id: [u8; 32] = [1u8; 32];
        let original = ProofState {
            name: "Proof of Reserves".to_string(),
            total_reserves: 1000000,
            total_token: 900000,
            ripcord: false,
            ripcord_details: vec![],
            timestamp: 1716153600,
        };

        let encoded = original.convert_to_hex_string_with_feed_id(&feed_id);
        println!("Encoded: {}", encoded);

        let (decoded, decoded_feed_id) = ProofState::decode_from_hex_string(&encoded).unwrap();
        println!("Decoded: {:?}", decoded);

        assert_eq!(original.name, decoded.name);
        assert_eq!(original.total_reserves, decoded.total_reserves);
        assert_eq!(original.total_token, decoded.total_token);
        assert_eq!(original.ripcord, decoded.ripcord);
        assert_eq!(original.ripcord_details, decoded.ripcord_details);
        assert_eq!(original.timestamp, decoded.timestamp);
        assert_eq!(feed_id, decoded_feed_id);
    }
}
