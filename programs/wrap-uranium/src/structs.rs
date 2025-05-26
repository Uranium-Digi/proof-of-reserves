use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub authority: Pubkey,
    pub wrap_authority: Pubkey,
    pub unwrap_authority: Pubkey,
}
