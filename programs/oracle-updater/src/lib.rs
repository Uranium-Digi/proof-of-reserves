use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::Instruction,
    program::{get_return_data, invoke},
    pubkey::Pubkey,
};
use chainlink_data_streams_report::report::v3::ReportDataV3;
use chainlink_solana_data_streams::VerifierInstructions;

pub mod instructions;
use instructions::*;

// Re-export types for external use
pub use instructions::{CompressedProof, ProofState, Reserves};

// https://docs.chain.link/data-streams/tutorials/streams-direct/solana-onchain-report-verification
declare_id!("2Yyp93nX4rJaN4eFE7AWMCRa4u4UBzAT4u2er8iNHu28");

#[program]
pub mod oracle_updater {
    use super::*;
    /// Verifies a Data Streams report using Cross-Program Invocation to the Verifier program
    /// Returns the decoded report data if verification succeeds
    pub fn verify(
        ctx: Context<ExampleProgramContext>,
        signed_report: Vec<u8>,
        compressed_proof: Vec<u8>,
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

            // The ProofState struct compressed must be constructed prior
            let compressed_proof_account = &mut ctx.accounts.compressed_proof;
            compressed_proof_account.compressed_proof = compressed_proof;
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
            msg!(
                "Compressed Proof: {:?}",
                compressed_proof_account.compressed_proof.clone()
            );

            let proof_state = compressed_proof_account.decode()?;
            msg!("Proof State: {:?}", proof_state);

            let reserves_account = &mut ctx.accounts.reserves_account;
            reserves_account.reserves = proof_state.total_reserves;

            msg!("Reserves Account: {:?}", reserves_account);
        } else {
            msg!("No report data found!");
            return Err(error!(CustomError::NoReportData));
        }
        Ok(())
    }

    // tells you the current reserves amount
    pub fn reserve_amount(ctx: Context<ReservesContext>) -> Result<()> {
        let reserves_account = &ctx.accounts.reserves_account;
        msg!("Reserves amount: {}", reserves_account.reserves);
        Ok(())
    }

    pub fn update_reserves_amount(ctx: Context<ReservesContext>, amount: u64) -> Result<()> {
        ctx.accounts.reserves_account.reserves = amount;
        Ok(())
    }
}
