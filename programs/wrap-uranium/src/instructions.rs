use anchor_lang::prelude::*;

use anchor_spl::{
    associated_token::AssociatedToken,
    token_2022::Token2022,
    token_interface::{Mint, TokenAccount},
};

use crate::{err::CustomError, structs::Config};

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        init,
        payer = signer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    /// CHECK: mint is not dangerous because we don't read or write from this account
    pub mint: AccountInfo<'info>,

    #[account(
        init, 
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        payer = signer, 
        mint::decimals = 9, 
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub wrapped_mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        init,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program
    )]
    pub mint_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        init, 
        payer = signer, 
        token::mint = mint,
        token::authority = config,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve", mint.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config", mint.key().as_ref()], 
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut, mint::decimals = 9)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct WithdrawMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config", mint.key().as_ref()], 
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut, mint::decimals = 9)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct DepositWrappedMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config", mint.key().as_ref()], 
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut, mint::decimals = 9)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::token_program = token_program
    )]
    pub wrapped_mint: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct WithdrawWrappedMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config", mint.key().as_ref()], 
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mint::decimals = 9)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::token_program = token_program
    )]
    pub wrapped_mint: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct SetConfig<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config", mint.key().as_ref()], 
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(mut, mint::decimals = 9)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_wrap_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_unwrap_authority: AccountInfo<'info>,

}

#[derive(Accounts)]
pub struct Wrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.wrap_authority @ CustomError::YouAreNotWrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(signer)]
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub wrapped_mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = owner,
        associated_token::token_program = token_program
    )]
    pub owner_ata: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: destination is not dangerous because we don't read or write from this account
    #[account()]
    pub destination: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = wrapped_mint,
        associated_token::authority = destination,
        associated_token::token_program = token_program
    )]
    pub destination_wrapped_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut, 
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program
    )]
    pub mint_ata: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Unwrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.wrap_authority @ CustomError::YouAreNotUnwrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(signer)]
    pub owner: Signer<'info>,

    #[account(
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub wrapped_mint: InterfaceAccount<'info, Mint>,

    /// CHECK: destination is not dangerous because we don't read or write from this account
    #[account()]
    pub destination: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = destination,
        associated_token::token_program = token_program
    )]
    pub destination_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut, 
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program
    )]
    pub mint_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = owner,
        associated_token::token_program = token_program
    )]
    pub owner_wrapped_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut, 
        token::mint = mint,
        token::authority = config,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve", mint.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct MintAndWrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config.wrap_authority @ CustomError::YouAreNotUnwrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        mint::decimals = 9,
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub wrapped_mint: InterfaceAccount<'info, Mint>,

    
    #[account(
        seeds = [b"issuance_wallet_pda", mint.key().as_ref()],
        bump,
    )]
    pub issuance_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = issuance_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub issuance_wallet_pda_wrapped_ata: InterfaceAccount<'info, TokenAccount>,
    

    /// CHECK: destination is not dangerous because we don't read or write from this account
    #[account()]
    pub master_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = master_wallet,
        associated_token::token_program = token_program
    )]
    pub master_wallet_wrapped_ata: InterfaceAccount<'info, TokenAccount>,

    #[account()]
    pub company_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program
    )]
    pub company_wallet_wrapped_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut, 
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program
    )]
    pub mint_ata: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub oracle_updater_program: AccountInfo<'info>,

    #[account(mut, seeds = [b"reserves"], bump, seeds::program = oracle_updater::ID)]
    pub reserves_account: Account<'info, oracle_updater::Reserves>,
}

#[derive(Accounts)]
pub struct UnwrapAndBurn<'info> {
    #[account(
        mut,
        constraint = owner.key() == config.unwrap_authority @ CustomError::YouAreNotUnwrapAuthority
    )]
    pub owner: Signer<'info>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = owner,
        associated_token::token_program = token_program
    )]
    pub owner_wrapped_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        seeds = [b"redemption_wallet_pda", mint.key().as_ref()],
        bump,
    )]
    pub redemption_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = redemption_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub redemption_wallet_pda_wrapped_ata: InterfaceAccount<'info, TokenAccount>,
    

    #[account()]
    pub company_wallet: AccountInfo<'info>,
    
    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program,
    )]
    pub company_wallet_wrapped_ata: InterfaceAccount<'info, TokenAccount>,


    #[account(
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        mint::decimals = 9,
        mint::token_program = token_program
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [b"wrapped_mint", mint.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config,
        mint::token_program = token_program
    )]
    pub wrapped_mint: InterfaceAccount<'info, Mint>,

    
    #[account(
        mut, 
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program
    )]
    pub mint_ata: InterfaceAccount<'info, TokenAccount>,


    #[account(
        mut, 
        token::mint = mint,
        token::authority = config,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve", mint.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}
