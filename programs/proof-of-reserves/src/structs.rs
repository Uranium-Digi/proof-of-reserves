use anchor_lang::prelude::*;

use crate::err::CustomError;

#[account]
#[derive(InitSpace, Debug)]
pub struct Config {
    pub authority: Pubkey,
    pub issue_authority: Pubkey,
    pub redeem_authority: Pubkey,
    pub update_authority: Pubkey,
    pub issuance_fee_rate: u16,
    pub redemption_fee_rate: u16,
    pub feed_id: [u8; 32],
    pub pending_authority: Pubkey,
    pub padding: [u8; 32],
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
}

#[account]
#[derive(Debug, InitSpace)]
pub struct Reserves {
    pub reserves: u64,
    pub last_updated: Option<i64>,
    /// The redeemed amount in the last issuance/redemption cycle
    pub pending_redemptions: u64,
    /// The last time the TNF was updated
    pub tnf_last_updated_at: u64,
    pub padding: [u8; 56],
}

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
    use anchor_lang::solana_program::native_token::LAMPORTS_PER_SOL;

    use super::*;
    #[test]
    fn test_proof_state_encoding_decoding() {
        let feed_id: [u8; 32] = [1u8; 32];
        let original = ProofState {
            name: "Uranium Proof of Reserves".to_string(),
            total_reserves: 13 * 10u64.pow(6) * LAMPORTS_PER_SOL,
            total_token: 12 * 10u64.pow(6) * LAMPORTS_PER_SOL,
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
