use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::{get_return_data, invoke},
    pubkey::Pubkey,
};
use chainlink_data_streams_report::report::v3::ReportDataV3;
use chainlink_solana_data_streams::VerifierInstructions;

declare_id!("8y6CXiQsLVXa98ASAeC9oMmo9GV7n7Z2mCwUJysYjUYs");

#[program]
pub mod oracle_updater {
    use super::*;

    /// Verifies a Data Streams report using Cross-Program Invocation to the Verifier program
    /// Returns the decoded report data if verification succeeds

    pub fn verify(
        ctx: Context<ExampleProgramContext>,
        signed_report: Vec<u8>,
        can_mint_amount: u64,
        can_burn_amount: u64,
        total_reserves: u64,
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

            let proof_state = &mut ctx.accounts.proof_state;

            proof_state.valid_from_timestamp = report.valid_from_timestamp;
            proof_state.observations_timestamp = report.observations_timestamp;
            proof_state.expires_at = report.expires_at;
            proof_state.can_mint_amount = can_mint_amount;
            proof_state.can_burn_amount = can_burn_amount;
            proof_state.total_reserves = total_reserves;

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
        space = 8 + std::mem::size_of::<ProofState>()
    )]
    pub proof_state: Account<'info, ProofState>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ProofState {
    // pub feed_id: ReportDataV3::feed_id::ID,
    // pub benchmark_price: u128,
    pub valid_from_timestamp: u32,
    pub observations_timestamp: u32,
    pub expires_at: u32,
    pub can_mint_amount: u64,
    pub can_burn_amount: u64,
    pub total_reserves: u64,
}

impl ProofState {
    // function to build proof state from a report
    // pub fn build_proof_state(
    //     report: &ReportDataV3,
    //     can_mint_amount: u128,
    //     can_burn_amount: u128,
    //     total_reserves: u128,
    // ) -> Self {
    //     Self {
    //         // feed_id: report.feed_id,
    //         // benchmark_price: report.benchmark_price,
    //         valid_from_timestamp: report.valid_from_timestamp,
    //         observations_timestamp: report.observations_timestamp,
    //         expires_at: report.expires_at,
    //         can_mint_amount,
    //         can_burn_amount,
    //         total_reserves,
    //     }
    // }
}
