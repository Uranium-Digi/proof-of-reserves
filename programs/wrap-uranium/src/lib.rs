use anchor_lang::prelude::*;

mod err;
mod instructions;
mod structs;
mod utils;

use instructions::*;

declare_id!("3JmfgAqnGnyh8pXGo8w8bi6MGjfd3Jn4aaKqfJgb7UcQ");

#[program]
pub mod wrap_uranium {
    use anchor_spl::token_2022::{
        burn, mint_to, set_authority,
        spl_token_2022::{extension::transfer_fee::TransferFeeConfig, instruction::AuthorityType},
        transfer_checked, Burn, MintTo, SetAuthority, TransferChecked,
    };
    use utils::{calculate_burn_amount, calculate_transfer_amount, get_mint_extension_data};

    use crate::err::CustomError;

    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.signer.key();
        ctx.accounts.config.wrap_authority = ctx.accounts.signer.key();
        ctx.accounts.config.unwrap_authority = ctx.accounts.signer.key();

        Ok(())
    }

    pub fn set_app_config(ctx: Context<SetConfig>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.new_authority.key();
        ctx.accounts.config.wrap_authority = ctx.accounts.new_wrap_authority.key();
        ctx.accounts.config.unwrap_authority = ctx.accounts.new_unwrap_authority.key();
        Ok(())
    }

    // mint -> wrapped_mint
    pub fn wrap(ctx: Context<Wrap>, token_amount: u64) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.owner_ata.to_account_info(),
                    to: ctx.accounts.mint_ata.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
            ),
            token_amount,
            9,
        )?;

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.wrapped_mint.to_account_info(),
                    to: ctx.accounts.destination_wrapped_ata.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            token_amount,
        )?;
        Ok(())
    }

    // wraped_mint -> mint
    pub fn unwrap(ctx: Context<Unwrap>, token_amount: u64) -> Result<()> {
        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.mint.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;

        let fee = transfer_fee_config.get_epoch_fee(epoch);
        let (amount_from_ata, amount_from_fee_reserve) =
            calculate_transfer_amount(&fee, token_amount)?;

        let balance_before = ctx.accounts.destination_ata.amount;

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.mint_ata.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            amount_from_ata,
            9,
        )?;

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.fee_rebate_reserve.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            amount_from_fee_reserve,
            9,
        )?;
        burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.wrapped_mint.to_account_info(),
                    from: ctx.accounts.owner_wrapped_ata.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
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

    pub fn mint_and_wrap(ctx: Context<MintAndWrap>, token_amount: u64) -> Result<()> {
        let supply = ctx.accounts.mint.supply;
        let new_supply = supply.checked_add(token_amount).unwrap(); // error if overflow
        let reserved = ctx.accounts.reserves_account.reserves;
        if new_supply > reserved {
            return Err(CustomError::InsufficientReserves.into());
        }

        mint_to(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.mint_ata.to_account_info(),
                    authority: ctx.accounts.mint_authority.to_account_info(),
                },
            ),
            token_amount,
        )?;

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.wrapped_mint.to_account_info(),
                    to: ctx.accounts.destination_wrapped_ata.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            token_amount,
        )?;
        Ok(())
    }

    pub fn unwrap_and_burn(ctx: Context<UnwrapAndBurn>, token_amount: u64) -> Result<()> {
        let epoch = Clock::get()?.epoch;
        let mint_data = &mut ctx.accounts.mint.to_account_info();
        let transfer_fee_config = get_mint_extension_data::<TransferFeeConfig>(mint_data)?;

        let fee = transfer_fee_config.get_epoch_fee(epoch);
        let (amount_from_ata, amount_from_fee_reserve) = calculate_burn_amount(&fee, token_amount)?;

        burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.wrapped_mint.to_account_info(),
                    from: ctx.accounts.owner_wrapped_ata.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
            ),
            token_amount,
        )?;

        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.mint_ata.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            amount_from_ata,
        )?;

        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.fee_rebate_reserve.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
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
                    account_or_mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.config.key()),
        )?;
        Ok(())
    }

    // Mint authority "config_pda" -> "signer"
    pub fn withdraw_mint_authority(ctx: Context<WithdrawMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.config.to_account_info(),
                    account_or_mint: ctx.accounts.mint.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.signer.key()),
        )?;
        Ok(())
    }

    pub fn deposit_wraped_mint_authority(ctx: Context<DepositWrapedMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.signer.to_account_info(),
                    account_or_mint: ctx.accounts.wrapped_mint.to_account_info(),
                },
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.config.key()),
        )?;
        Ok(())
    }

    pub fn withdraw_wraped_mint_authority(ctx: Context<WithdrawWrapedMintAuthority>) -> Result<()> {
        set_authority(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                SetAuthority {
                    current_authority: ctx.accounts.config.to_account_info(),
                    account_or_mint: ctx.accounts.wrapped_mint.to_account_info(),
                },
                &[&[
                    b"config",
                    ctx.accounts.mint.key().as_ref(),
                    &[ctx.bumps.config],
                ]],
            ),
            AuthorityType::MintTokens,
            Some(ctx.accounts.signer.key()),
        )?;
        Ok(())
    }
}
