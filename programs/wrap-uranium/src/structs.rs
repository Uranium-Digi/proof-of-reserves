use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub authority: Pubkey,
    pub wrap_authority: Pubkey,
    pub unwrap_authority: Pubkey,
    pub issuance_fee_rate: u16,
    pub redemption_fee_rate: u16,
    pub padding: [u8; 64],
}
