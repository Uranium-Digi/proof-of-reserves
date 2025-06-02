use anchor_lang::prelude::*;

mod err;
mod instructions;
mod structs;
mod utils;

use instructions::*;

declare_id!("6L33NZbnBxjerCLA4g5rVpHUc1LM4D6gQRrsxYi9zqj8");

#[program]
pub mod wrap_uranium {
    use anchor_spl::token_2022::{
        burn, mint_to, set_authority,
        spl_token_2022::{extension::transfer_fee::TransferFeeConfig, instruction::AuthorityType},
        transfer_checked, Burn, MintTo, SetAuthority, TransferChecked,
    };
    use utils::{calculate_burn_amount, calculate_transfer_amount, get_mint_extension_data};

    use crate::{
        err::CustomError,
        utils::{calculate_issuance_fee, calculate_redemption_fee},
    };

    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.config_pda.authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.wrap_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.unwrap_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.mint_and_wrap_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.unwrap_and_burn_authority = ctx.accounts.signer.key();
        ctx.accounts.config_pda.issuance_fee_rate = 0;
        ctx.accounts.config_pda.redemption_fee_rate = 0;
        Ok(())
    }

    pub fn set_app_config(
        ctx: Context<SetConfig>,
        new_issuance_fee_rate: u16,
        new_redemption_fee_rate: u16,
    ) -> Result<()> {
        ctx.accounts.config_pda.authority = ctx.accounts.new_authority.key();
        ctx.accounts.config_pda.wrap_authority = ctx.accounts.new_wrap_authority.key();
        ctx.accounts.config_pda.unwrap_authority = ctx.accounts.new_unwrap_authority.key();
        ctx.accounts.config_pda.mint_and_wrap_authority =
            ctx.accounts.new_mint_and_wrap_authority.key();
        ctx.accounts.config_pda.unwrap_and_burn_authority =
            ctx.accounts.new_unwrap_and_burn_authority.key();
        ctx.accounts.config_pda.issuance_fee_rate = new_issuance_fee_rate;
        ctx.accounts.config_pda.redemption_fee_rate = new_redemption_fee_rate;
        Ok(())
    }

    // mint -> wrapped_mint
    pub fn wrap(ctx: Context<Wrap>, token_amount: u64) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.signer_ata.to_account_info(),
                    to: ctx.accounts.config_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(),
                },
            ),
            token_amount,
            ctx.accounts.u.decimals,
        )?;

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.wu.to_account_info(),
                    to: ctx.accounts.destination_wu_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            token_amount,
        )?;
        Ok(())
    }

    // wraped_mint -> mint
    pub fn unwrap(ctx: Context<Unwrap>, token_amount: u64) -> Result<()> {
        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.u.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;

        let fee = transfer_fee_config.get_epoch_fee(epoch);
        let (amount_from_ata, amount_from_fee_reserve) =
            calculate_transfer_amount(&fee, token_amount)?;

        let balance_before = ctx.accounts.destination_ata.amount;

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.config_pda_u_ata.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            amount_from_ata,
            ctx.accounts.u.decimals,
        )?;

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.fee_rebate_reserve_u_ata.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            amount_from_fee_reserve,
            ctx.accounts.u.decimals,
        )?;
        burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.signer_wu_ata.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(),
                },
            ),
            token_amount,
        )?;

        // reload the account balance after the transfer CPI call and make sure the amount is correct
        ctx.accounts.destination_ata.reload()?;
        let balance_after = ctx.accounts.destination_ata.amount;
        assert_eq!(balance_after - balance_before, token_amount);

        Ok(())
    }

    pub fn mint_and_wrap(ctx: Context<MintAndWrap>, gross_issue: u64) -> Result<()> {
        let supply = ctx.accounts.u.supply;
        let new_supply = supply.checked_add(gross_issue).unwrap(); // error if overflow
        let reserved = ctx.accounts.reserves_pda.reserves;
        if new_supply > reserved {
            return Err(CustomError::InsufficientReserves.into());
        }
        // calculate fees now
        let (issuance_fee, receivable) = calculate_issuance_fee(
            gross_issue,
            ctx.accounts.config_pda.issuance_fee_rate as u64,
        )?;

        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.u.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;
        let tx_fee_config = transfer_fee_config.get_epoch_fee(epoch);
        let mintable = tx_fee_config
            .calculate_post_fee_amount(gross_issue)
            .unwrap();
        let expected_transfer_fee = gross_issue - mintable;

        // Minting the mintable amount of U token to config_pda_u_ata
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.u.to_account_info(),
                    to: ctx.accounts.config_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            mintable,
        )?;

        // Minting the transfer_fee amount of U token to the fee rebate reserve
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.u.to_account_info(),
                    to: ctx.accounts.fee_rebate_reserve_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            expected_transfer_fee,
        )?;

        // Minting the wU token to the issuance wallet pda wrapped ata
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.wu.to_account_info(),
                    to: ctx.accounts.issuance_wallet_pda_wu_ata.to_account_info(),
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

        // Transfer the wU token from the issuance wallet pda wrapped ata to the company wallet wrapped ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.issuance_wallet_pda_wu_ata.to_account_info(),
                    to: ctx.accounts.company_wallet_wu_ata.to_account_info(),
                    authority: ctx.accounts.issuance_wallet_pda.to_account_info(),
                },
                &[&[
                    b"issuance_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.issuance_wallet_pda],
                ]],
            ),
            issuance_fee,
            ctx.accounts.wu.decimals,
        )?;
        // Transfer the wU token from the issuance wallet pda wrapped ata to the master wallet wrapped ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.issuance_wallet_pda_wu_ata.to_account_info(),
                    to: ctx.accounts.master_wallet_wu_ata.to_account_info(),
                    authority: ctx.accounts.issuance_wallet_pda.to_account_info(),
                },
                &[&[
                    b"issuance_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.issuance_wallet_pda],
                ]],
            ),
            receivable,
            ctx.accounts.wu.decimals,
        )?;

        Ok(())
    }

    pub fn unwrap_and_burn(ctx: Context<UnwrapAndBurn>, gross_redeem: u64) -> Result<()> {
        // calculation redemption fees

        let (redemption_fee, redeemable) = calculate_redemption_fee(
            gross_redeem,
            ctx.accounts.config_pda.redemption_fee_rate as u64,
        )?;

        // Transfer the wU token from the owner wrapped ata to the redemption wallet pda wrapped ata
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.signer_wu_ata.to_account_info(),
                    to: ctx.accounts.redemption_wallet_pda_wu_ata.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(),
                },
            ),
            gross_redeem,
            ctx.accounts.wu.decimals,
        )?;

        // Transfer the wU token from the redemption wallet pda wrapped ata to the company wallet wrapped ata
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.redemption_wallet_pda_wu_ata.to_account_info(),
                    to: ctx.accounts.company_wallet_wu_ata.to_account_info(),
                    authority: ctx.accounts.redemption_wallet_pda.to_account_info(),
                },
                &[&[
                    b"redemption_wallet_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.redemption_wallet_pda],
                ]],
            ),
            redemption_fee,
            ctx.accounts.wu.decimals,
        )?;

        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.u.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;

        let fee = transfer_fee_config.get_epoch_fee(epoch);
        let (amount_from_ata, amount_from_fee_reserve) = calculate_burn_amount(&fee, redeemable)?;

        // Burn the wU from the redemption wallet pda wrapped ata
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.redemption_wallet_pda_wu_ata.to_account_info(),
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

        // Burning the U token from the mint wrapped ata
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.config_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            amount_from_ata,
        )?;

        // Burning the wU token from the fee rebate reserve
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.fee_rebate_reserve_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            amount_from_fee_reserve,
        )?;

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

    pub fn deposit_wrapped_mint_authority(ctx: Context<DepositWrappedMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.signer.to_account_info(),
                    account_or_mint: ctx.accounts.wu.to_account_info(),
                },
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.config_pda.key()),
        )?;
        Ok(())
    }

    pub fn withdraw_wrapped_mint_authority(
        ctx: Context<WithdrawWrappedMintAuthority>,
    ) -> Result<()> {
        set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.config_pda.to_account_info(),
                    account_or_mint: ctx.accounts.wu.to_account_info(),
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

    pub fn top_up_rebate_reserves(
        ctx: Context<TopUpRebateReserves>,
        wrapped_token_amount: u64,
    ) -> Result<()> {
        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.u.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;

        let fee = transfer_fee_config.get_epoch_fee(epoch);
        let u_amount_actually_transfered = fee
            .calculate_post_fee_amount(wrapped_token_amount)
            .ok_or(CustomError::InvalidFee)?;

        let balance_before = ctx.accounts.fee_rebate_reserve_u_ata.amount;

        // Transferring U tokens from the main pool in the wrap_uranium program to the fee rebate reserve
        // Although we are transferring wrapped_token_amount of U, the amount of U that lands will actually be less due to fees
        // In the unwrap function, we make up the difference by rebating the fees from the fee_rebate_reserve.
        // Here, we just NOT do that rebating.
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.u.to_account_info(),
                    from: ctx.accounts.config_pda_u_ata.to_account_info(),
                    to: ctx.accounts.fee_rebate_reserve_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            wrapped_token_amount,
            ctx.accounts.u.decimals,
        )?;

        // // This uses the fee_rebate_reserve to compensate for amount lost to fees
        // So here, we just NOT do it.
        // transfer_checked(
        //     CpiContext::new_with_signer(
        //         ctx.accounts.token_program.to_account_info(),
        //         TransferChecked {
        //             mint: ctx.accounts.u.to_account_info(),
        //             from: ctx.accounts.fee_rebate_reserve.to_account_info(),
        //             to: ctx.accounts.destination_ata.to_account_info(),
        //             authority: ctx.accounts.config_pda.to_account_info(),
        //         },
        //         &[&[
        //             b"config_pda",
        //             ctx.accounts.u.key().as_ref(),
        //             &[ctx.bumps.config_pda],
        //         ]],
        //     ),
        //     amount_from_fee_reserve,
        //     ctx.accounts.u.decimals,
        // )?;

        // Burn the wU token from the owner wrapped ata
        burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.wu.to_account_info(),
                    from: ctx.accounts.signer_wu_ata.to_account_info(),
                    authority: ctx.accounts.signer.to_account_info(),
                },
            ),
            wrapped_token_amount,
        )?;

        // reload the account balance after the transfer CPI call and make sure the amount is correct

        // The expected behaviour is that the 1 U tran
        ctx.accounts.fee_rebate_reserve_u_ata.reload()?;
        let balance_after = ctx.accounts.fee_rebate_reserve_u_ata.amount;
        assert_eq!(balance_after - balance_before, u_amount_actually_transfered);

        Ok(())
    }
}
