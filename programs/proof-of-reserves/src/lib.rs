use anchor_lang::prelude::*;

mod err;
mod events;
mod instructions;
mod structs;
mod utils;

use instructions::*;

pub use events::*;
pub use structs::*;

declare_id!("PoR33sfFS2u5pAWAF4oHvEsKLZUfwEP1eXrbKFVjBGN");

const INIT_AUTHORITY: Pubkey =
    Pubkey::from_str_const("defFk42U9xo1iev3eqSzPHmwqdeJwHgPnZDtxZ9oKGN");

#[program]
pub mod proof_of_reserves {
    use anchor_lang::solana_program::program::{get_return_data, invoke};

    use anchor_spl::token::{
        burn, mint_to, set_authority, spl_token::instruction::AuthorityType, transfer_checked,
        Burn, MintTo, SetAuthority, TransferChecked,
    };

    use chainlink_data_streams_report::report::v9::ReportDataV9;
    use chainlink_solana_data_streams::VerifierInstructions;

    use num_bigint::BigInt;
    use num_traits::ToPrimitive;
    use spl_tlv_account_resolution::solana_instruction::Instruction;

    use crate::{
        err::CustomError,
        utils::{calculate_issuance_fee, calculate_redemption_fee},
    };

    use super::*;

    pub fn initialize(ctx: Context<Initialize>, feed_id: Vec<u8>) -> Result<()> {
        ctx.accounts.config_pda.authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.update_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.issue_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.redeem_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.issuance_fee_rate = 0;
        ctx.accounts.config_pda.redemption_fee_rate = 0;
        ctx.accounts.config_pda.feed_id = feed_id[..32].try_into().unwrap();
        Ok(())
    }

    pub fn set_app_config(
        ctx: Context<SetConfig>,
        new_issuance_fee_rate: u16,
        new_redemption_fee_rate: u16,
        feed_id: Vec<u8>,
    ) -> Result<()> {
        if new_issuance_fee_rate > 10_000 || new_redemption_fee_rate > 10_000 {
            return Err(CustomError::InvalidFeeRate.into());
        }
        ctx.accounts.config_pda.issue_authority = ctx.accounts.new_issue_authority.key();
        ctx.accounts.config_pda.redeem_authority = ctx.accounts.new_redeem_authority.key();
        ctx.accounts.config_pda.update_authority = ctx.accounts.new_update_authority.key();
        ctx.accounts.config_pda.issuance_fee_rate = new_issuance_fee_rate;
        ctx.accounts.config_pda.redemption_fee_rate = new_redemption_fee_rate;
        ctx.accounts.config_pda.feed_id = feed_id[..32].try_into().unwrap();
        Ok(())
    }

    pub fn set_pending_authority(ctx: Context<SetPendingAuthority>) -> Result<()> {
        ctx.accounts.config_pda.pending_authority = ctx.accounts.new_pending_authority.key();
        Ok(())
    }

    pub fn accept_authority(ctx: Context<AcceptAuthority>) -> Result<()> {
        if ctx.accounts.config_pda.pending_authority == Pubkey::default() {
            return Err(CustomError::NoPendingAuthority.into());
        }
        ctx.accounts.config_pda.authority = ctx.accounts.config_pda.pending_authority;
        ctx.accounts.config_pda.pending_authority = Pubkey::default();
        Ok(())
    }

    pub fn issue(ctx: Context<Issue>, gross_issue: u64, issuance_id: String) -> Result<()> {
        let supply = ctx.accounts.u.supply;
        let new_supply = supply.checked_add(gross_issue).unwrap(); // error if overflow
                                                                   // let reserved = ctx.accounts.reserves_pda.reserves;
        let effective_reserves = ctx
            .accounts
            .reserves_pda
            .reserves
            .checked_sub(ctx.accounts.reserves_pda.pending_redemptions)
            .unwrap(); // error if underflow

        if new_supply > effective_reserves {
            return Err(CustomError::InsufficientReserves.into());
        }
        // calculate fees now
        let (issuance_fee, receivable) = calculate_issuance_fee(
            gross_issue,
            ctx.accounts.config_pda.issuance_fee_rate as u64,
        )?;

        // Minting the gross_issue amount of U token to issuance_wallet_pda_u_ata
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.u.to_account_info(),
                    to: ctx.accounts.issuance_wallet_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            gross_issue,
        )?;

        // Transfer the Issuance Fee (U token) from the issuance wallet pda U ata to the company wallet U ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.issuance_wallet_pda_u_ata.to_account_info(),
                    to: ctx.accounts.company_wallet_u_ata.to_account_info(),
                    authority: ctx.accounts.issuance_wallet_pda.to_account_info(),
                },
                &[&[
                    b"issuance_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.issuance_wallet_pda],
                ]],
            ),
            issuance_fee,
            ctx.accounts.u.decimals,
        )?;

        // Transfer the U token from the issuance wallet pda wrapped ata to the master wallet U ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.issuance_wallet_pda_u_ata.to_account_info(),
                    to: ctx.accounts.master_wallet_u_ata.to_account_info(),
                    authority: ctx.accounts.issuance_wallet_pda.to_account_info(),
                },
                &[&[
                    b"issuance_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.issuance_wallet_pda],
                ]],
            ),
            receivable,
            ctx.accounts.u.decimals,
        )?;

        emit!(IssueEvent {
            mint: ctx.accounts.u.key().to_string(),
            gross_issue,
            issuance_fee,
            issuance_id,
            created_at: Clock::get().unwrap().unix_timestamp,
        });

        Ok(())
    }

    pub fn redeem(ctx: Context<Redeem>, gross_redeem: u64, redemption_id: String) -> Result<()> {
        // calculation redemption fees
        let (redemption_fee, redeemable) = calculate_redemption_fee(
            gross_redeem,
            ctx.accounts.config_pda.redemption_fee_rate as u64,
        )?;
        // add to pending_redemptions
        let pending_redemptions = ctx.accounts.reserves_pda.pending_redemptions;
        ctx.accounts.reserves_pda.pending_redemptions =
            pending_redemptions.checked_add(redeemable).unwrap(); // redeemable not gross_redeem

        // Transfer the U token from the signer U ata to the redemption wallet pda U ata
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.signer_u_ata.to_account_info(),
                    to: ctx.accounts.redemption_wallet_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(),
                },
            ),
            gross_redeem,
            ctx.accounts.u.decimals,
        )?;

        // Transfer the Redemption Fee (U token) from the redemption wallet pda U ata to the company wallet U ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.redemption_wallet_pda_u_ata.to_account_info(),
                    to: ctx.accounts.company_wallet_u_ata.to_account_info(),
                    authority: ctx.accounts.redemption_wallet_pda.to_account_info(),
                },
                &[&[
                    b"redemption_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.redemption_wallet_pda],
                ]],
            ),
            redemption_fee,
            ctx.accounts.u.decimals,
        )?;

        // Burn the U from the redemption wallet pda U ata
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.redemption_wallet_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.redemption_wallet_pda.to_account_info(),
                },
                &[&[
                    b"redemption_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.redemption_wallet_pda],
                ]],
            ),
            redeemable,
        )?;

        emit!(RedeemEvent {
            mint: ctx.accounts.u.key().to_string(),
            gross_redeem,
            redemption_fee,
            redemption_id,
            created_at: Clock::get().unwrap().unix_timestamp,
        });

        Ok(())
    }

    // Mint authority "signer" -> "config_pda"
    pub fn deposit_mint_authority(ctx: Context<DepositMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.signer.to_account_info(),
                    account_or_mint: ctx.accounts.u.to_account_info(),
                },
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.config_pda.key()),
        )?;
        Ok(())
    }

    // Mint authority "config_pda" -> "signer"
    pub fn withdraw_mint_authority(ctx: Context<WithdrawMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.config_pda.to_account_info(),
                    account_or_mint: ctx.accounts.u.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.signer.key()),
        )?;
        Ok(())
    }

    pub fn verify(
        ctx: Context<Verify>,
        signed_report: Vec<u8>,
        // only for deduplication purposes
        tnf_last_updated_at: u64,
    ) -> Result<()> {
        if ctx.accounts.reserves_pda.tnf_last_updated_at >= tnf_last_updated_at {
            return Err(error!(CustomError::ReportAlreadyVerified));
        }
        let program_id = ctx.accounts.verifier_program_id.key();
        let verifier_account = ctx.accounts.verifier_account.key();
        let access_controller = ctx.accounts.access_controller.key();
        let user = ctx.accounts.user.key();
        let config_account = ctx.accounts.verifier_config_account.key();
        let now = Clock::get().unwrap().unix_timestamp;

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
                ctx.accounts.verifier_config_account.to_account_info(),
            ],
        )?;

        // Decode and log the verified report data
        let Some((_program_id, return_data)) = get_return_data() else {
            msg!("No report data found!");
            return Err(error!(CustomError::NoReportData));
        };

        let compressed_proof_account = &mut ctx.accounts.compressed_proof;

        msg!("Report data found!");
        let report = ReportDataV9::decode(&return_data)
            .map_err(|_| error!(CustomError::InvalidReportData))?;
        compressed_proof_account.compressed_proof = return_data;

        // The AUM is in 18 decimals, but the reserves are in 9 decimals
        let new_reserves = report
            .aum
            .checked_div(&BigInt::from(10u32.pow(9)))
            .and_then(|x| x.to_u64())
            .ok_or(error!(CustomError::InvalidReportData))?;

        // Log report fields
        msg!("Report: {:?}", report);
        msg!("New reserves {:?}", new_reserves);

        assert!(ctx.accounts.u.supply <= new_reserves);

        if ctx.accounts.config_pda.feed_id != report.feed_id.0 {
            return Err(error!(CustomError::InvalidReportData));
        }

        if let Some(last_update) = ctx.accounts.reserves_pda.last_updated {
            if last_update >= report.observations_timestamp as i64 {
                return Err(error!(CustomError::InvalidReportData));
            }
        }

        if report.valid_from_timestamp > now as u32 {
            return Err(error!(CustomError::InvalidReportData));
        }

        if report.valid_from_timestamp < tnf_last_updated_at as u32 {
            return Err(error!(CustomError::InvalidReportData));
        }

        let reserves_prev = ctx.accounts.reserves_pda.reserves;

        ctx.accounts.reserves_pda.reserves = new_reserves;
        ctx.accounts.reserves_pda.last_updated = Some(report.observations_timestamp as i64);
        // clear the pending_redemptions after updating the reserves
        ctx.accounts.reserves_pda.pending_redemptions = 0;
        ctx.accounts.reserves_pda.tnf_last_updated_at = tnf_last_updated_at;

        msg!("Config PDA: {:?}", ctx.accounts.config_pda);
        msg!("Reserves Account: {:?}", ctx.accounts.reserves_pda);

        emit!(VerifyEvent {
            mint: ctx.accounts.u.key().to_string(),
            total_reserves: new_reserves,
            total_reserves_prev: reserves_prev,
            total_supply: ctx.accounts.u.supply,
            created_at: now,
        });

        Ok(())
    }
}
