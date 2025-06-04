use anchor_lang::prelude::*;

mod err;
mod instructions;
mod structs;
mod utils;

use instructions::*;

declare_id!("6HP4rFEb9v9yiSkgRTHXvYCsEAx6pxqaF7R4dyK2s7BV");

#[program]
pub mod wrap_uranium {
    use anchor_spl::{
        token_2022::{
            burn, mint_to, set_authority, spl_token_2022::instruction::AuthorityType,
            transfer_checked, Burn, MintTo, SetAuthority, TransferChecked,
        },
        token_interface::{
            withdraw_withheld_tokens_from_accounts, withdraw_withheld_tokens_from_mint,
            WithdrawWithheldTokensFromAccounts, WithdrawWithheldTokensFromMint,
        },
    };

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
                    from: ctx.accounts.owner_u_ata.to_account_info(),
                    to: ctx.accounts.config_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
            ),
            token_amount,
            ctx.accounts.u.decimals,
        )?;

        // rebate the transfer tax into config_pda_u_ata,
        // this will make the wrapped amount 100% goes into the config_pda_u_ata
        withdraw_withheld_tokens_from_accounts(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                WithdrawWithheldTokensFromAccounts {
                    mint: ctx.accounts.u.to_account_info(),
                    destination: ctx.accounts.config_pda_u_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            vec![ctx.accounts.config_pda_u_ata.to_account_info()],
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
            token_amount,
            ctx.accounts.u.decimals,
        )?;

        // rebate the transfer tax into destination_ata
        // this will make the unwrapped amount 100% goes into the destination_ata
        withdraw_withheld_tokens_from_accounts(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                WithdrawWithheldTokensFromAccounts {
                    mint: ctx.accounts.u.to_account_info(),
                    destination: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            vec![ctx.accounts.destination_ata.to_account_info()],
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

        // Minting the gross_issue amount of U token to config_pda_u_ata
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
            gross_issue,
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

        // Burning the U token from the config_pda_u_ata
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
            redeemable,
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

    pub fn deposit_withdraw_withheld_authority(
        ctx: Context<DepositWithdrawWithheldAuthority>,
    ) -> Result<()> {
        set_authority(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.signer.to_account_info(),
                    account_or_mint: ctx.accounts.u.to_account_info(),
                },
            ),
            AuthorityType::WithheldWithdraw,
            Some(ctx.accounts.config_pda.key()),
        )?;
        Ok(())
    }

    pub fn withdraw_withdraw_withheld_authority(
        ctx: Context<WithdrawWithdrawWithheldAuthority>,
    ) -> Result<()> {
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
            AuthorityType::WithheldWithdraw,
            Some(ctx.accounts.signer.key()),
        )?;
        Ok(())
    }

    // collect all the withheld tokens from the `remaining_accounts` and send them to the `destination` account
    pub fn collect_withheld_tokens_from_accounts<'info>(
        ctx: Context<'_, '_, '_, 'info, CollectWithheldTokensFromAccounts<'info>>,
    ) -> Result<()> {
        withdraw_withheld_tokens_from_accounts(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                WithdrawWithheldTokensFromAccounts {
                    mint: ctx.accounts.u.to_account_info(),
                    destination: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            ctx.remaining_accounts.to_vec(),
        )?;
        Ok(())
    }

    // collect all the withheld tokens from the `remaining_accounts` and send them to the `destination` account
    pub fn collect_withheld_tokens_from_mint(
        ctx: Context<CollectWithheldTokensFromMint>,
    ) -> Result<()> {
        withdraw_withheld_tokens_from_mint(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            WithdrawWithheldTokensFromMint {
                mint: ctx.accounts.u.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.config_pda.to_account_info(),
                token_program_id: ctx.accounts.token_program.to_account_info(),
            },
            &[&[
                b"config_pda",
                ctx.accounts.u.key().as_ref(),
                &[ctx.bumps.config_pda],
            ]],
        ))?;
        Ok(())
    }

    // collect all the withheld tokens from the `destination` account and send them to the `destination` account
    pub fn rebate_withheld_tokens(ctx: Context<RebateWithheldTokens>) -> Result<()> {
        withdraw_withheld_tokens_from_accounts(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                WithdrawWithheldTokensFromAccounts {
                    mint: ctx.accounts.u.to_account_info(),
                    destination: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.config_pda.to_account_info(),
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                },
                &[&[
                    b"config_pda",
                    ctx.accounts.u.key().as_ref(),
                    &[ctx.bumps.config_pda],
                ]],
            ),
            vec![ctx.accounts.destination.to_account_info()],
        )?;
        Ok(())
    }
}
