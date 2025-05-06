use anchor_lang::prelude::*;

declare_id!("Hjd7xmM1oU47c9bP2qPG28G8LFTAcoi3qX5K8TvxshEE");

#[program]
pub mod oracle_updater {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }

    pub fn update_oracle(ctx: Context<UpdateOracle>) -> Result<()> {}

    pub fn verify_report(ctx: Context<VerifyReport>) -> Result<()> {}
}

#[derive(Accounts)]
pub struct Initialize {}
