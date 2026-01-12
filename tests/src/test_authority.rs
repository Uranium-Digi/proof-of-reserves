use std::sync::Arc;

use anchor_client::{
    anchor_lang::solana_program,
    solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signer::Signer},
    Client, Cluster,
};

use anchor_spl::token::spl_token;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    message::{v0::Message, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    signature::{read_keypair_file, Keypair, Signature},
    signers::Signers,
    system_instruction::create_account,
    transaction::VersionedTransaction,
};

const WALLET_KEY: &str = "ANCHOR_WALLET";

async fn send_tx<T: Signers + ?Sized>(
    rpc: &RpcClient,
    ixs: Vec<Instruction>,
    payer: &Pubkey,
    signer: &T,
) -> Signature {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let message = Message::try_compile(&payer, &ixs, &[], blockhash).unwrap();
    let v0_message = VersionedMessage::V0(message);
    let tx = VersionedTransaction::try_new(v0_message, signer).unwrap();

    let tx_id = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .inspect_err(|e| println!("Error: {:#?}", e))
        .unwrap();
    tx_id
}

async fn try_send_tx<T: Signers + ?Sized>(
    rpc: &RpcClient,
    ixs: Vec<Instruction>,
    payer: &Pubkey,
    signer: &T,
) -> Result<Signature, solana_client::client_error::ClientError> {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let message = Message::try_compile(&payer, &ixs, &[], blockhash).unwrap();
    let v0_message = VersionedMessage::V0(message);
    let tx = VersionedTransaction::try_new(v0_message, signer).unwrap();

    rpc.send_and_confirm_transaction(&tx).await
}

async fn setup_test() -> (Arc<Keypair>, Keypair, Pubkey, anchor_client::Program<Arc<Keypair>>) {
    let program_id = proof_of_reserves::ID;
    let anchor_wallet = std::env::var(WALLET_KEY).unwrap();
    let signer = read_keypair_file(&anchor_wallet).unwrap();
    let signer = Arc::new(signer);

    let u = Keypair::new();

    let client =
        Client::new_with_options(Cluster::Localnet, signer.clone(), CommitmentConfig::processed());

    let program = client.program(program_id).unwrap();
    let rpc = program.rpc();

    rpc.request_airdrop(&signer.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    let config_pda =
        Pubkey::find_program_address(&[b"config_pda", u.pubkey().as_ref()], &program_id).0;

    let space = spl_token::state::Mint::LEN;
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();

    // Initialize mint and config
    let mut ixs = vec![
        create_account(
            &signer.pubkey(),
            &u.pubkey(),
            rent,
            space as u64,
            &spl_token::ID,
        ),
        spl_token::instruction::initialize_mint(
            &spl_token::ID,
            &u.pubkey(),
            &signer.pubkey(),
            Some(&signer.pubkey()),
            9,
        )
        .unwrap(),
    ];

    ixs.append(
        &mut program
            .request()
            .accounts(proof_of_reserves::accounts::Initialize {
                signer: signer.pubkey(),
                u: u.pubkey(),
                config_pda,
                system_program: solana_program::system_program::ID,
            })
            .args(proof_of_reserves::instruction::Initialize {
                feed_id: vec![0u8; 32],
            })
            .instructions()
            .unwrap(),
    );

    let tx = send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &u]).await;
    rpc.confirm_transaction_with_spinner(
        &tx,
        &rpc.get_latest_blockhash().await.unwrap(),
        CommitmentConfig::finalized(),
    )
    .await
    .unwrap();

    (signer, u, config_pda, program)
}

#[tokio::test]
async fn test_authority_transfer_success() {
    let (signer, u, config_pda, program) = setup_test().await;
    let rpc = program.rpc();

    let new_authority = Keypair::new();
    rpc.request_airdrop(&new_authority.pubkey(), 2 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    // Step 1: Current authority sets pending authority
    println!("Setting pending authority...");
    {
        let ixs = program
            .request()
            .accounts(proof_of_reserves::accounts::SetPendingAuthority {
                signer: signer.pubkey(),
                config_pda,
                u: u.pubkey(),
                new_pending_authority: new_authority.pubkey(),
            })
            .args(proof_of_reserves::instruction::SetPendingAuthority {})
            .instructions()
            .unwrap();

        let tx = send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        rpc.confirm_transaction_with_spinner(
            &tx,
            &rpc.get_latest_blockhash().await.unwrap(),
            CommitmentConfig::finalized(),
        )
        .await
        .unwrap();
    }

    // Verify pending authority is set
    let config: proof_of_reserves::Config = program.account(config_pda).await.unwrap();
    assert_eq!(config.pending_authority, new_authority.pubkey());
    assert_eq!(config.authority, signer.pubkey());
    println!("Pending authority set successfully");

    // Step 2: New authority accepts
    println!("Accepting authority...");
    {
        let ixs = program
            .request()
            .accounts(proof_of_reserves::accounts::AcceptAuthority {
                signer: new_authority.pubkey(),
                config_pda,
                u: u.pubkey(),
            })
            .args(proof_of_reserves::instruction::AcceptAuthority {})
            .instructions()
            .unwrap();

        let tx = send_tx(&rpc, ixs, &new_authority.pubkey(), &[&new_authority]).await;
        rpc.confirm_transaction_with_spinner(
            &tx,
            &rpc.get_latest_blockhash().await.unwrap(),
            CommitmentConfig::finalized(),
        )
        .await
        .unwrap();
    }

    // Verify authority has changed and pending is cleared
    let config: proof_of_reserves::Config = program.account(config_pda).await.unwrap();
    assert_eq!(config.authority, new_authority.pubkey());
    assert_eq!(config.pending_authority, Pubkey::default());
    println!("Authority transfer completed successfully");
}

#[tokio::test]
async fn test_set_pending_authority_unauthorized() {
    let (signer, u, config_pda, program) = setup_test().await;
    let rpc = program.rpc();

    let unauthorized = Keypair::new();
    rpc.request_airdrop(&unauthorized.pubkey(), 2 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    let new_authority = Keypair::new();

    // Try to set pending authority with unauthorized signer
    println!("Attempting unauthorized set_pending_authority...");
    let ixs = program
        .request()
        .accounts(proof_of_reserves::accounts::SetPendingAuthority {
            signer: unauthorized.pubkey(),
            config_pda,
            u: u.pubkey(),
            new_pending_authority: new_authority.pubkey(),
        })
        .args(proof_of_reserves::instruction::SetPendingAuthority {})
        .instructions()
        .unwrap();

    let result = try_send_tx(&rpc, ixs, &unauthorized.pubkey(), &[&unauthorized]).await;
    assert!(result.is_err(), "Expected transaction to fail");
    println!("Unauthorized set_pending_authority correctly rejected");

    // Verify authority unchanged
    let config: proof_of_reserves::Config = program.account(config_pda).await.unwrap();
    assert_eq!(config.authority, signer.pubkey());
    assert_eq!(config.pending_authority, Pubkey::default());
}

#[tokio::test]
async fn test_accept_authority_unauthorized() {
    let (signer, u, config_pda, program) = setup_test().await;
    let rpc = program.rpc();

    let new_authority = Keypair::new();
    let unauthorized = Keypair::new();

    rpc.request_airdrop(&new_authority.pubkey(), 2 * LAMPORTS_PER_SOL)
        .await
        .unwrap();
    rpc.request_airdrop(&unauthorized.pubkey(), 2 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    // First set pending authority correctly
    println!("Setting pending authority...");
    {
        let ixs = program
            .request()
            .accounts(proof_of_reserves::accounts::SetPendingAuthority {
                signer: signer.pubkey(),
                config_pda,
                u: u.pubkey(),
                new_pending_authority: new_authority.pubkey(),
            })
            .args(proof_of_reserves::instruction::SetPendingAuthority {})
            .instructions()
            .unwrap();

        let tx = send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        rpc.confirm_transaction_with_spinner(
            &tx,
            &rpc.get_latest_blockhash().await.unwrap(),
            CommitmentConfig::finalized(),
        )
        .await
        .unwrap();
    }

    // Try to accept with wrong signer (not the pending authority)
    println!("Attempting unauthorized accept_authority...");
    let ixs = program
        .request()
        .accounts(proof_of_reserves::accounts::AcceptAuthority {
            signer: unauthorized.pubkey(),
            config_pda,
            u: u.pubkey(),
        })
        .args(proof_of_reserves::instruction::AcceptAuthority {})
        .instructions()
        .unwrap();

    let result = try_send_tx(&rpc, ixs, &unauthorized.pubkey(), &[&unauthorized]).await;
    assert!(result.is_err(), "Expected transaction to fail");
    println!("Unauthorized accept_authority correctly rejected");

    // Verify authority unchanged
    let config: proof_of_reserves::Config = program.account(config_pda).await.unwrap();
    assert_eq!(config.authority, signer.pubkey());
    assert_eq!(config.pending_authority, new_authority.pubkey());
}

#[tokio::test]
async fn test_accept_authority_no_pending() {
    let (signer, u, config_pda, program) = setup_test().await;
    let rpc = program.rpc();

    // Try to accept authority when no pending authority is set
    println!("Attempting accept_authority with no pending authority...");
    let ixs = program
        .request()
        .accounts(proof_of_reserves::accounts::AcceptAuthority {
            signer: signer.pubkey(),
            config_pda,
            u: u.pubkey(),
        })
        .args(proof_of_reserves::instruction::AcceptAuthority {})
        .instructions()
        .unwrap();

    let result = try_send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    assert!(result.is_err(), "Expected transaction to fail when no pending authority");
    println!("Accept authority with no pending correctly rejected");
}

#[tokio::test]
async fn test_old_authority_cannot_act_after_transfer() {
    let (signer, u, config_pda, program) = setup_test().await;
    let rpc = program.rpc();

    let new_authority = Keypair::new();
    rpc.request_airdrop(&new_authority.pubkey(), 2 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    // Complete the authority transfer
    {
        let ixs = program
            .request()
            .accounts(proof_of_reserves::accounts::SetPendingAuthority {
                signer: signer.pubkey(),
                config_pda,
                u: u.pubkey(),
                new_pending_authority: new_authority.pubkey(),
            })
            .args(proof_of_reserves::instruction::SetPendingAuthority {})
            .instructions()
            .unwrap();

        let tx = send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        rpc.confirm_transaction_with_spinner(
            &tx,
            &rpc.get_latest_blockhash().await.unwrap(),
            CommitmentConfig::finalized(),
        )
        .await
        .unwrap();
    }

    {
        let ixs = program
            .request()
            .accounts(proof_of_reserves::accounts::AcceptAuthority {
                signer: new_authority.pubkey(),
                config_pda,
                u: u.pubkey(),
            })
            .args(proof_of_reserves::instruction::AcceptAuthority {})
            .instructions()
            .unwrap();

        let tx = send_tx(&rpc, ixs, &new_authority.pubkey(), &[&new_authority]).await;
        rpc.confirm_transaction_with_spinner(
            &tx,
            &rpc.get_latest_blockhash().await.unwrap(),
            CommitmentConfig::finalized(),
        )
        .await
        .unwrap();
    }

    // Old authority tries to set pending authority again
    println!("Old authority attempting to set pending authority...");
    let another_new = Keypair::new();
    let ixs = program
        .request()
        .accounts(proof_of_reserves::accounts::SetPendingAuthority {
            signer: signer.pubkey(),
            config_pda,
            u: u.pubkey(),
            new_pending_authority: another_new.pubkey(),
        })
        .args(proof_of_reserves::instruction::SetPendingAuthority {})
        .instructions()
        .unwrap();

    let result = try_send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    assert!(result.is_err(), "Old authority should not be able to set pending authority");
    println!("Old authority correctly rejected after transfer");

    // Verify new authority is still in control
    let config: proof_of_reserves::Config = program.account(config_pda).await.unwrap();
    assert_eq!(config.authority, new_authority.pubkey());
}
