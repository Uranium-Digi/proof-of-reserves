use anchor_lang::prelude::*;

use anchor_spl::{
    associated_token::AssociatedToken,
    token_2022::Token2022,
    token_interface::{Mint, TokenAccount},
};

use crate::{err::CustomError, structs::Config};

// *********** Naming Convention ***********
// {authority}_{is_pda}_{token}_{is_ata}
// eg: signer_u_ata, config_pda_u_ata
//
// special case: fee_rebate_reserve_u_ata

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    /// CHECK: mint is not dangerous because we don't read or write from this account
    pub u: AccountInfo<'info>,

    #[account(
        init, 
        seeds = [b"wu", u.key().as_ref()],
        bump,
        payer = signer, 
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        init,
        payer = signer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(
        init,
        payer = signer,
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        init, 
        payer = signer, 
        token::mint = u,
        token::authority = config_pda,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve_u_ata", u.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct WithdrawMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda:Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct DepositWithdrawWithheldAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct DepositWrappedMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct WithdrawWrappedMintAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct SetConfig<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.authority @ CustomError::YouAreNotAdmin
    )]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_wrap_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_unwrap_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_mint_and_wrap_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_unwrap_and_burn_authority: AccountInfo<'info>,

}

#[derive(Accounts)]
pub struct Wrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.wrap_authority || signer.key() == config_pda.mint_and_wrap_authority @ CustomError::YouAreNotWrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(signer)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = owner,
        associated_token::token_program = token_program
    )]
    pub owner_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut,
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: destination is not dangerous because we don't read or write from this account
    #[account()]
    pub destination: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = wu,
        associated_token::authority = destination,
        associated_token::token_program = token_program
    )]
    pub destination_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Unwrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.unwrap_authority || signer.key() == config_pda.unwrap_and_burn_authority @ CustomError::YouAreNotUnwrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut,
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: destination is not dangerous because we don't read or write from this account
    #[account()]
    pub destination: AccountInfo<'info>,

    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = u,
        associated_token::authority = destination,
        associated_token::token_program = token_program
    )]
    pub destination_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = signer,
        associated_token::token_program = token_program
    )]
    pub signer_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        token::mint = u,
        token::authority = config_pda,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve_u_ata", u.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct MintAndWrap<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.mint_and_wrap_authority @ CustomError::YouAreNotMintAndWrapAuthority
    )]
    pub signer: Signer<'info>,

    #[account(
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(
        mut,
        mint::decimals = 9,
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut, 
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,


    #[account(
        mut,
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: issuance_wallet_pda is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"issuance_wallet_pda", u.key().as_ref()],
        bump,
    )]
    pub issuance_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = issuance_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub issuance_wallet_pda_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    

    /// CHECK: master_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub master_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = master_wallet,
        associated_token::token_program = token_program
    )]
    pub master_wallet_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,


    /// CHECK: company_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub company_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program
    )]
    pub company_wallet_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        token::mint = u,
        token::authority = config_pda,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve_u_ata", u.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(address = oracle_updater::ID)]
    pub oracle_updater_program: AccountInfo<'info>,

    #[account(mut, seeds = [b"reserves"], bump, seeds::program = oracle_updater::ID)]
    pub reserves_pda: Box<Account<'info, oracle_updater::Reserves>>,
}

#[derive(Accounts)]
pub struct UnwrapAndBurn<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.unwrap_and_burn_authority @ CustomError::YouAreNotUnwrapAndBurnAuthority
    )]
    pub signer: Signer<'info>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = signer,
        associated_token::token_program = token_program
    )]
    pub signer_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    

    #[account(
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(
        mut,
        mint::decimals = 9,
        mint::token_program = token_program
    )]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut, 
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,


    #[account(
        mut,
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: redemption_wallet_pda is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"redemption_wallet_pda", u.key().as_ref()],
        bump,
    )]
    pub redemption_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = redemption_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub redemption_wallet_pda_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    
    /// CHECK: company_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub company_wallet: AccountInfo<'info>,
    
    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program,
    )]
    pub company_wallet_wu_ata:Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        token::mint = u,
        token::authority = config_pda,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve_u_ata", u.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct TopUpRebateReserves<'info> {
    #[account(signer)]
    pub signer: Signer<'info>,

    #[account(
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mint::decimals = 9)]
    pub u: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [b"wu", u.key().as_ref()],
        bump,
        mint::decimals = 9, 
        mint::authority = config_pda,
        mint::token_program = token_program
    )]
    pub wu: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut, 
        associated_token::mint = u,
        associated_token::authority = config_pda,
        associated_token::token_program = token_program
    )]
    pub config_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::mint = wu,
        associated_token::authority = signer,
        associated_token::token_program = token_program
    )]
    pub signer_wu_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut, 
        token::mint = u,
        token::authority = config_pda,
        token::token_program = token_program,
        seeds = [b"fee_rebate_reserve_u_ata", u.key().as_ref()],
        bump
    )]
    pub fee_rebate_reserve_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}
