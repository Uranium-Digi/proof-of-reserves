use std::{str::FromStr, sync::Arc};

use anchor_client::{
    anchor_lang::solana_program,
    solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signer::Signer},
    Client, Cluster,
};

use anchor_spl::{
    associated_token::spl_associated_token_account::{
        self, get_associated_token_address_with_program_id,
        instruction::{
            create_associated_token_account, create_associated_token_account_idempotent,
        },
    },
    token::spl_token,
};
use hex_literal::hex;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    bpf_loader_upgradeable,
    instruction::Instruction,
    message::{v0::Message, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    signature::{read_keypair_file, Keypair, Signature},
    signers::Signers,
    system_instruction::create_account,
    transaction::VersionedTransaction,
};

use access_controller::AccessController;
use transmitter::transmitter::transmitter::{Transmitter, DEFAULT_HEX_STRING};
use verifier::state::VerifierAccount;

const WALLET_KEY: &str = "ANCHOR_WALLET";

async fn init_chainlink_verifier(signer: &Keypair) -> Pubkey {
    let client =
        Client::new_with_options(Cluster::Localnet, &signer, CommitmentConfig::processed());

    let verifier_program = client.program(verifier::ID).unwrap();
    let access_controller_program = client.program(access_controller::ID).unwrap();
    let access_controller_data_account = Keypair::new();

    let rpc = verifier_program.rpc();
    let space = 8 + std::mem::size_of::<AccessController>();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    let mut ixs = vec![create_account(
        &signer.pubkey(),
        &access_controller_data_account.pubkey(),
        rent,
        space as u64,
        &access_controller::ID,
    )];

    let mut init_access_controller_ix = access_controller_program
        .request()
        .accounts(access_controller::accounts::Initialize {
            state: access_controller_data_account.pubkey(),
            owner: signer.pubkey(),
        })
        .args(access_controller::instruction::Initialize {})
        .instructions()
        .unwrap();

    ixs.append(&mut init_access_controller_ix);

    let mut add_access_ix = access_controller_program
        .request()
        .accounts(access_controller::accounts::AddAccess {
            state: access_controller_data_account.pubkey(),
            owner: signer.pubkey(),
            address: signer.pubkey(), // this is the transmitter address
        })
        .args(access_controller::instruction::AddAccess {})
        .instructions()
        .unwrap();

    ixs.append(&mut add_access_ix);

    let verifier_account = Pubkey::find_program_address(&[b"verifier"], &verifier::ID).0;

    let rpc = verifier_program.rpc();
    let (verifier_program_data, _) =
        Pubkey::find_program_address(&[verifier::ID.as_ref()], &bpf_loader_upgradeable::id());

    let mut init_verifier_ix = verifier_program
        .request()
        .accounts(verifier::accounts::InitializeContext {
            owner: signer.pubkey(),
            verifier_account,
            program_data: verifier_program_data,
            program: verifier::ID,
            system_program: solana_program::system_program::ID,
        })
        .args(verifier::instruction::Initialize {})
        .instructions()
        .unwrap();

    ixs.append(&mut init_verifier_ix);

    let target_size = 8 + std::mem::size_of::<VerifierAccount>();
    let mut current_size = VerifierAccount::INIT_SPACE;
    const REALLOC_INCREMENT: usize = 10 * 1024;

    // Perform reallocation in increments
    while current_size < target_size {
        current_size = std::cmp::min(current_size + REALLOC_INCREMENT, target_size);

        let mut realloc_ix = verifier_program
            .request()
            .accounts(verifier::accounts::ReallocContext {
                owner: signer.pubkey(),
                verifier_account,
                program_data: verifier_program_data,
                program: verifier::ID,
                system_program: solana_program::system_program::ID,
            })
            .args(verifier::instruction::ReallocAccount {
                _len: current_size as u32,
            })
            .instructions()
            .unwrap();

        ixs.append(&mut realloc_ix);
    }

    let mut init_verifier_data_ix = verifier_program
        .request()
        .accounts(verifier::accounts::InitializeAccountDataContext {
            owner: signer.pubkey(),
            verifier_account,
            access_controller: None,
            program: verifier::ID,
            program_data: verifier_program_data,
            system_program: solana_program::system_program::ID,
        })
        .args(verifier::instruction::InitializeAccountData {})
        .instructions()
        .unwrap();

    ixs.append(&mut init_verifier_data_ix);

    let report_signers: Vec<[u8; 20]> = vec![
        hex!("6b23132dece4da06571ba9149e2986549cb5fb30"),
        hex!("72cce7298ae2f6e516be2f2343ebedf863548d12"),
        hex!("87abf51625b8587a8b331b305d026bb48772a20c"),
        hex!("dd3210a31d062cada9f37c69305032b7e5594e25"),
    ];

    let mut set_config_ix = verifier_program
        .request()
        .accounts(verifier::accounts::UpdateConfigContext {
            owner: signer.pubkey(),
            verifier_account,
        })
        .args(verifier::instruction::SetConfigWithActivationTime {
            signers: report_signers,
            activation_time: 0,
            f: 1,
        })
        .instructions()
        .unwrap();

    ixs.append(&mut set_config_ix);

    let signature = send_tx(
        &rpc,
        ixs,
        &signer.pubkey(),
        &[&signer, &access_controller_data_account],
    )
    .await;

    println!("✅ Access Controller initialized, waiting for confirmation...");
    rpc.confirm_transaction_with_spinner(
        &signature,
        &rpc.get_latest_blockhash().await.unwrap(),
        CommitmentConfig::finalized(),
    )
    .await
    .unwrap();

    access_controller_data_account.pubkey()
}

#[tokio::test]
async fn test_initialize() {
    let program_id = proof_of_reserves::ID;
    let anchor_wallet = std::env::var(WALLET_KEY).unwrap();
    let signer = read_keypair_file(&anchor_wallet).unwrap();
    let signer = Arc::new(signer);

    // Initialize Chainlink Verifier
    let access_controller_data_account = init_chainlink_verifier(&signer).await;

    let u = Keypair::new();

    let master_wallet = Keypair::new();
    let company_wallet = Keypair::new();

    let issuance_wallet_pda =
        Pubkey::find_program_address(&[b"issuance_wallet_pda", u.pubkey().as_ref()], &program_id).0;

    let redemption_wallet_pda = Pubkey::find_program_address(
        &[b"redemption_wallet_pda", u.pubkey().as_ref()],
        &program_id,
    )
    .0;

    let client =
        Client::new_with_options(Cluster::Localnet, &signer, CommitmentConfig::processed());

    let program = client.program(program_id).unwrap();

    let rpc = program.rpc();

    rpc.request_airdrop(&signer.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    rpc.request_airdrop(&master_wallet.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    let config_pda =
        Pubkey::find_program_address(&[b"config_pda", u.pubkey().as_ref()], &program_id).0;

    let signer_ata =
        get_associated_token_address_with_program_id(&signer.pubkey(), &u.pubkey(), &spl_token::ID);

    let signer_u_ata =
        get_associated_token_address_with_program_id(&signer.pubkey(), &u.pubkey(), &spl_token::ID);

    let master_wallet_u_ata = get_associated_token_address_with_program_id(
        &master_wallet.pubkey(),
        &u.pubkey(),
        &spl_token::ID,
    );

    let company_wallet_u_ata = get_associated_token_address_with_program_id(
        &company_wallet.pubkey(),
        &u.pubkey(),
        &spl_token::ID,
    );

    let issuance_wallet_pda_u_ata = get_associated_token_address_with_program_id(
        &issuance_wallet_pda,
        &u.pubkey(),
        &spl_token::ID,
    );

    let redemption_wallet_pda_u_ata = get_associated_token_address_with_program_id(
        &redemption_wallet_pda,
        &u.pubkey(),
        &spl_token::ID,
    );

    // print all pda and ata
    println!("config_pda: {:?}", config_pda);
    println!("issuance_wallet_pda: {:?}", issuance_wallet_pda);
    println!("issuance_wallet_pda_u_ata: {:?}", issuance_wallet_pda_u_ata);
    println!("master_wallet_u_ata: {:?}", master_wallet_u_ata);
    println!("company_wallet_u_ata: {:?}", company_wallet_u_ata);
    println!("issuance_wallet_pda_u_ata: {:?}", issuance_wallet_pda_u_ata);
    println!("redemption_wallet_pda: {:?}", redemption_wallet_pda);
    println!(
        "redemption_wallet_pda_u_ata: {:?}",
        redemption_wallet_pda_u_ata
    );

    let space = spl_token::state::Mint::LEN;

    let rent = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    println!("Initializing");
    {
        // Init mint with transfer fee
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
                &u.pubkey(),            // Mint address
                &signer.pubkey(),       // Mint authority
                Some(&signer.pubkey()), // Freeze authority
                9,                      // Decimals
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
                    feed_id: hex::decode(
                        "0009fffb1e3bd8e3948987ceb484b7e0153ddcfaf6c22290f4240616891c14c3",
                    )
                    .unwrap(),
                })
                .instructions()
                .unwrap(),
        );

        // This is just for the tests - at launch this will not be necessary
        println!("Minting to signer");
        ixs.push(create_associated_token_account(
            &signer.pubkey(), // ata rent payer
            &signer.pubkey(), // owner
            &u.pubkey(),
            &spl_token::ID,
        ));
        ixs.push(
            spl_token::instruction::mint_to(
                &spl_token::ID,
                &u.pubkey(),
                &signer_ata,      // ata
                &signer.pubkey(), // mint authority
                &[],
                100 * LAMPORTS_PER_SOL,
            )
            .unwrap(),
        );

        println!("Depositing mint authority");
        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::DepositMintAuthority {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    token_program: spl_token::ID,
                })
                .args(proof_of_reserves::instruction::DepositMintAuthority {})
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
    }

    println!("Set Config to bad values");
    {
        let mut ixs = vec![];
        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::SetConfig {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    new_authority: signer.pubkey(),
                    new_issue_authority: u.pubkey(),
                    new_redeem_authority: u.pubkey(),
                })
                .args(proof_of_reserves::instruction::SetAppConfig {
                    new_issuance_fee_rate: 1u16,
                    new_redemption_fee_rate: 1u16,
                    feed_id: [0u8; 32].to_vec(),
                })
                .instructions()
                .unwrap(),
        );
        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    }

    println!("Set Config to good values");
    {
        let mut ixs = vec![];
        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::SetConfig {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    new_authority: signer.pubkey(),
                    new_issue_authority: signer.pubkey(),
                    new_redeem_authority: signer.pubkey(),
                })
                .args(proof_of_reserves::instruction::SetAppConfig {
                    new_issuance_fee_rate: 0u16,
                    new_redemption_fee_rate: 0u16,
                    feed_id: vec![
                        0, 9, 255, 251, 30, 59, 216, 227, 148, 137, 135, 206, 180, 132, 183, 224,
                        21, 61, 220, 250, 246, 194, 34, 144, 244, 36, 6, 22, 137, 28, 20, 195,
                    ],
                })
                .instructions()
                .unwrap(),
        );
        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    }

    println!("Withdraw Mint Authority");
    {
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::WithdrawMintAuthority {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    token_program: spl_token::ID,
                })
                .args(proof_of_reserves::instruction::WithdrawMintAuthority {})
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    }
    println!("Deposit Mint Authority again");
    {
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::DepositMintAuthority {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    token_program: spl_token::ID,
                })
                .args(proof_of_reserves::instruction::DepositMintAuthority {})
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    }

    println!("Verify");
    // Verify the "DEFAULT_HEX_STRING" report and populate the reserves account
    // This need to be call after initialize
    let tx = Transmitter::new(
        Cluster::Localnet,
        signer.clone(),
        program_id,
        u.pubkey(),
        verifier::ID,
        access_controller::ID,
        access_controller_data_account,
    )
    .unwrap()
    .verify(DEFAULT_HEX_STRING)
    .await
    .unwrap();
    rpc.confirm_transaction_with_spinner(
        &tx,
        &rpc.get_latest_blockhash().await.unwrap(),
        CommitmentConfig::finalized(),
    )
    .await
    .unwrap();

    println!("Issue");
    {
        let reserves_pda =
            Pubkey::find_program_address(&[b"reserves", u.pubkey().as_ref()], &program_id).0;

        println!("reserves_account: {:?}", &reserves_pda);
        let mut ixs = vec![];

        // create issuance_wallet_pda_wrapped_ata
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &&issuance_wallet_pda,
            &u.pubkey(),
            &spl_token::ID,
        ));

        // create company_wallet_wrapped_ata
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &company_wallet.pubkey(),
            &u.pubkey(),
            &spl_token::ID,
        ));

        // create master_wallet_wrapped_ata
        ixs.push(create_associated_token_account_idempotent(
            &signer.pubkey(),
            &master_wallet.pubkey(),
            &u.pubkey(),
            &spl_token::ID,
        ));

        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::Issue {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    issuance_wallet_pda,
                    issuance_wallet_pda_u_ata,
                    master_wallet: master_wallet.pubkey(),
                    master_wallet_u_ata,
                    company_wallet: company_wallet.pubkey(),
                    company_wallet_u_ata,
                    token_program: spl_token::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                    reserves_pda,
                })
                .args(proof_of_reserves::instruction::Issue {
                    gross_issue: 100 * LAMPORTS_PER_SOL,
                    issuance_id: "issuance_id".to_string(),
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        let master_wallet_ata_balance = rpc
            .get_token_account_balance(&master_wallet_u_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        assert_eq!(master_wallet_ata_balance, 100 * LAMPORTS_PER_SOL,);
    }

    println!("Redeem");
    {
        let mut ixs = vec![];
        // create company
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &redemption_wallet_pda,
            &u.pubkey(),
            &spl_token::ID,
        ));

        let reserves_pda =
            Pubkey::find_program_address(&[b"reserves", u.pubkey().as_ref()], &program_id).0;

        ixs.append(
            &mut program
                .request()
                .accounts(proof_of_reserves::accounts::Redeem {
                    signer: signer.pubkey(),
                    signer_u_ata,
                    config_pda,
                    u: u.pubkey(),
                    redemption_wallet_pda,
                    redemption_wallet_pda_u_ata,
                    reserves_pda,
                    company_wallet: company_wallet.pubkey(),
                    company_wallet_u_ata,
                    token_program: spl_token::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(proof_of_reserves::instruction::Redeem {
                    gross_redeem: 100 * LAMPORTS_PER_SOL,
                    redemption_id: "redemption_id".to_string(),
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        let signer_ata_balance = rpc
            .get_token_account_balance(&signer_u_ata)
            .await
            .unwrap()
            .amount
            .parse::<i64>()
            .unwrap();

        assert_eq!(signer_ata_balance, 0);
    }
}

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

async fn read_devnet_chainlink_signers() {
    let signer = Keypair::new();
    let dev_net_client = Client::new(Cluster::Devnet, &signer);
    let verifier_program_devnet = dev_net_client.program(verifier::ID).unwrap();
    let devnet_verifier = verifier_program_devnet
        .account::<VerifierAccount>(
            Pubkey::from_str("HJR45sRiFdGncL69HVzRK4HLS2SXcVW3KeTPkp2aFmWC").unwrap(),
        )
        .await
        .unwrap();

    for config in devnet_verifier.don_configs.iter() {
        for signer in config.signers.iter() {
            println!("signer: {:#?}", hex::encode(signer.key));
        }
    }
}
