use anchor_lang::prelude::*;

use anchor_spl::{
    associated_token::AssociatedToken,
    token::Token,
    token_interface::{Mint, TokenAccount},
};

use crate::{err::CustomError, structs::{CompressedProof, Config, Reserves}, INIT_AUTHORITY};

// *********** Naming Convention ***********
// {authority}_{is_pda}_{token}_{is_ata}
// eg: signer_u_ata, config_pda_u_ata

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut, constraint = signer.key() == INIT_AUTHORITY @ CustomError::YouAreNotAdmin)]
    pub signer: Signer<'info>,

    /// CHECK: mint is not dangerous because we don't read or write from this account
    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        init,
        payer = signer,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositMintAuthority<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut, 
        seeds = [b"config_pda", u.key().as_ref()], 
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,

    #[account(mut, mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Program<'info, Token>,
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

    pub token_program: Program<'info, Token>,
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

    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_issue_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_redeem_authority: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_update_authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SetPendingAuthority<'info> {
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

    /// CHECK: This is not dangerous because we don't read or write from this account
    pub new_pending_authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct AcceptAuthority<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.pending_authority @ CustomError::YouAreNotPendingAuthority
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
}

#[derive(Accounts)]
pub struct Issue<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.issue_authority @ CustomError::YouAreNotIssueAuthority
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

    /// CHECK: issuance_wallet_pda is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"issuance_wallet_pda", u.key().as_ref()],
        bump,
    )]
    pub issuance_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = issuance_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub issuance_wallet_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    

    /// CHECK: master_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub master_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = master_wallet,
        associated_token::token_program = token_program
    )]
    pub master_wallet_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,


    /// CHECK: company_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub company_wallet: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program
    )]
    pub company_wallet_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    #[account(mut, seeds = [b"reserves", u.key().as_ref()], bump)]
    pub reserves_pda: Box<Account<'info, Reserves>>,
}

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(
        mut,
        constraint = signer.key() == config_pda.redeem_authority @ CustomError::YouAreNotRedeemAuthority
    )]
    pub signer: Signer<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = signer,
        associated_token::token_program = token_program
    )]
    pub signer_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,

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

    /// CHECK: redemption_wallet_pda is not dangerous because we don't read or write from this account
    #[account(
        seeds = [b"redemption_wallet_pda", u.key().as_ref()],
        bump,
    )]
    pub redemption_wallet_pda: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = redemption_wallet_pda,
        associated_token::token_program = token_program
    )]
    pub redemption_wallet_pda_u_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    
    /// CHECK: company_wallet is not dangerous because we don't read or write from this account
    #[account()]
    pub company_wallet: AccountInfo<'info>,
    
    #[account(
        mut,
        associated_token::mint = u,
        associated_token::authority = company_wallet,
        associated_token::token_program = token_program,
    )]
    pub company_wallet_u_ata:Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut, seeds = [b"reserves", u.key().as_ref()], bump)]
    pub reserves_pda: Box<Account<'info, Reserves>>,
    
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct Verify<'info> {
    /// The Verifier Account stores the DON's public keys and other verification parameters.
    /// This account must match the PDA derived from the verifier program.
    /// CHECK: The account is validated by the verifier program.
    pub verifier_account: AccountInfo<'info>,
    /// The Access Controller Account
    /// /// CHECK: The account structure is validated by the verifier program.
    pub access_controller: AccountInfo<'info>,

    #[account(mint::decimals = 9)]
    pub u: Box<InterfaceAccount<'info, Mint>>,

    #[account(mut, constraint = user.key() == config_pda.update_authority.key() @ CustomError::YouAreNotUpdateAuthority)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config_pda", u.key().as_ref()],
        bump,
    )]
    pub config_pda: Box<Account<'info, Config>>,
    /// The Config Account is a PDA derived from a signed report
    /// CHECK: the account is validated by the verifier program.
    pub verifier_config_account: AccountInfo<'info>,
    /// The Verifier Program ID specifies the target Chainlink Data Streams Verifier program
    /// CHECK: The program ID is checked
    #[account(constraint = verifier_program_id.key() == verifier::ID @ CustomError::InvalidProgramId)]
    pub verifier_program_id: AccountInfo<'info>,
    /// PDA that stores the last verified report
    #[account(
        init_if_needed,
        seeds=[b"proof_v4", u.key().as_ref()],
        bump,
        payer = user,
        space = 8 + 4 + 1024 // space = 8 + std::mem::size_of::<CompressedProof>()
    )]
    pub compressed_proof: Account<'info, CompressedProof>, // should be an account

    #[account(
        init_if_needed,
        seeds=[b"reserves", u.key().as_ref()],
        bump,
        payer = user,
        space = 8 + Reserves::INIT_SPACE,
    )]
    pub reserves_pda: Box<Account<'info, Reserves>>,
    pub system_program: Program<'info, System>,
}
