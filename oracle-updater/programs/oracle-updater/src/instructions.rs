use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;

use hex;

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
        seeds=[b"proof_v4"],
        bump,
        payer = user,
        space = 8 + 4 + 1024 // space = 8 + std::mem::size_of::<CompressedProof>()
    )]
    pub compressed_proof: Account<'info, CompressedProof>, // should be an account

    #[account(init_if_needed,
        seeds=[b"mintable_account"],
        bump,
        payer = user,
        space = 8 + 8,
    )]
    pub mintable_account: Account<'info, Mintable>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(Debug)]
pub struct CompressedProof {
    // Store as raw bytes intead of
    // pub compressed_proof: [u8; 1024],
    pub compressed_proof: Vec<u8>,
}

impl CompressedProof {
    pub fn decode(&self) -> Result<ProofState> {
        let (proof_state, _) = ProofState::decode(&self.compressed_proof)?;
        Ok(proof_state)
    }
    pub fn calculate_mintable(&self) -> Result<u64> {
        let proof_state = self.decode()?;
        let mintable = proof_state
            .total_reserves
            .saturating_sub(proof_state.total_token);
        Ok(mintable)
    }
}

#[derive(Accounts)]
pub struct MintableContext<'info> {
    #[account(mut, seeds=[b"mintable_account"], bump)]
    pub mintable_account: Account<'info, Mintable>,
}

#[account]
#[derive(Debug)]
pub struct Mintable {
    pub mintable: u64,
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
    pub const DEFAULT_FEED_ID: &'static str =
        "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782";

    pub fn encode(&self, feed_id: &[u8; 32]) -> Vec<u8> {
        // pub fn convert_to_hex_string_with_feed_id(&self, feed_id: &[u8; 32]) -> String {
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
        bytes
        // hex::encode(bytes)
    }

    pub fn decode(compressed_proof: &Vec<u8>) -> Result<(Self, [u8; 32])> {
        let hex = &hex::encode(compressed_proof);
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

        let num_details =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut ripcord_details = Vec::new();
        for _ in 0..num_details {
            let detail_len =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
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
    #[test]
    fn test_proof_state_encoding_decoding() {
        let feed_id: [u8; 32] = [1u8; 32];
        let original = ProofState {
            name: "Proof of Reserves".to_string(),
            total_reserves: 1000000,
            total_token: 900000,
            ripcord: false,
            ripcord_details: vec![],
            timestamp: 1716153600,
        };

        let encoded = original.encode(&feed_id);
        println!("Encoded: {:?}", encoded);

        let (decoded, decoded_feed_id) = ProofState::decode(&encoded).unwrap();

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
