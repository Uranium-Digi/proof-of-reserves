use std::str::FromStr;

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
    token_2022::spl_token_2022::{self, instruction::transfer_checked},
};
use hex_literal::hex;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    bpf_loader_upgradeable,
    instruction::Instruction,
    message::{v0::Message, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
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
// #[test]
async fn test_initialize() {
    let program_id = wrap_uranium::ID;
    let anchor_wallet = std::env::var(WALLET_KEY).unwrap();
    let signer = read_keypair_file(&anchor_wallet).unwrap();

    // Initialize Chainlink Verifier
    let access_controller = init_chainlink_verifier(&signer).await;

    // Verify the "DEFAULT_HEX_STRING" report and populate the reserves account
    Transmitter::new(Some(Cluster::Localnet), Some(WALLET_KEY.to_string()))
        .unwrap()
        .verify(DEFAULT_HEX_STRING, Some(access_controller))
        .await
        .unwrap();

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

    let wu = Pubkey::find_program_address(&[b"wu", u.pubkey().as_ref()], &program_id).0;

    let config_pda =
        Pubkey::find_program_address(&[b"config_pda", u.pubkey().as_ref()], &program_id).0;

    let fee_rebate_reserve_u_ata = Pubkey::find_program_address(
        &[b"fee_rebate_reserve_u_ata", u.pubkey().as_ref()],
        &program_id,
    )
    .0;

    let config_pda_u_ata = get_associated_token_address_with_program_id(
        &config_pda, // owner
        &u.pubkey(), // mint
        &spl_token_2022::ID,
    );

    let signer_ata = get_associated_token_address_with_program_id(
        &signer.pubkey(),
        &u.pubkey(),
        &spl_token_2022::ID,
    );

    let signer_wu_ata =
        get_associated_token_address_with_program_id(&signer.pubkey(), &wu, &spl_token_2022::ID);

    let master_wallet_wu_ata = get_associated_token_address_with_program_id(
        &master_wallet.pubkey(),
        &wu,
        &spl_token_2022::ID,
    );

    let master_wallet_ata = get_associated_token_address_with_program_id(
        &master_wallet.pubkey(),
        &u.pubkey(),
        &spl_token_2022::ID,
    );

    let company_wallet_wu_ata = get_associated_token_address_with_program_id(
        &company_wallet.pubkey(),
        &wu,
        &spl_token_2022::ID,
    );

    let issuance_wallet_pda_wu_ata = get_associated_token_address_with_program_id(
        &issuance_wallet_pda,
        &wu,
        &spl_token_2022::ID,
    );

    let redemption_wallet_pda_wu_ata = get_associated_token_address_with_program_id(
        &redemption_wallet_pda,
        &wu,
        &spl_token_2022::ID,
    );

    let extension_types = vec![spl_token_2022::extension::ExtensionType::TransferFeeConfig];
    let space = spl_token_2022::extension::ExtensionType::try_calculate_account_len::<
        spl_token_2022::state::Mint,
    >(&extension_types)
    .unwrap();

    let rent = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    println!("Initializing");
    {
        let mut ixs = vec![
            create_account(
                &signer.pubkey(),
                &u.pubkey(),
                rent,
                space as u64,
                &spl_token_2022::ID,
            ),
            // Init mint with transfer fee
            spl_token_2022::extension::transfer_fee::instruction::initialize_transfer_fee_config(
                &spl_token_2022::ID,
                &u.pubkey(),
                Some(&signer.pubkey()),   // Transfer fee authority
                Some(&signer.pubkey()),   // Withdraw withheld fee authority
                1000,                     // Fee bps
                10000 * LAMPORTS_PER_SOL, // Max fee
            )
            .unwrap(),
            spl_token_2022::instruction::initialize_mint(
                &spl_token_2022::ID,
                &u.pubkey(),      // Mint address
                &signer.pubkey(), // Mint authority
                None,             // Freeze authority
                9,                // Decimals
            )
            .unwrap(),
        ];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Initialize {
                    signer: signer.pubkey(),
                    u: u.pubkey(),
                    wu,
                    config_pda,
                    config_pda_u_ata,
                    fee_rebate_reserve_u_ata,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::Initialize {})
                .instructions()
                .unwrap(),
        );
        println!("Minting to fee rebate reserve");

        ixs.push(
            spl_token_2022::instruction::mint_to(
                &spl_token_2022::ID,
                &u.pubkey(),
                &fee_rebate_reserve_u_ata,
                &signer.pubkey(),
                &[],
                1_000_000 * LAMPORTS_PER_SOL,
            )
            .unwrap(),
        );

        println!("Minting to signer");
        ixs.push(create_associated_token_account(
            &signer.pubkey(), // ata rent payer
            &signer.pubkey(), // owner
            &u.pubkey(),
            &spl_token_2022::ID,
        ));
        ixs.push(
            spl_token_2022::instruction::mint_to(
                &spl_token_2022::ID,
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
                .accounts(wrap_uranium::accounts::DepositMintAuthority {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    token_program: spl_token_2022::ID,
                })
                .args(wrap_uranium::instruction::DepositMintAuthority {})
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &u]).await;
    }

    println!("Wrapping");
    {
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Wrap {
                    signer: signer.pubkey(),
                    signer_ata,
                    u: u.pubkey(),
                    wu,
                    config_pda,
                    config_pda_u_ata,
                    destination: master_wallet.pubkey(),
                    destination_wu_ata: master_wallet_wu_ata,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::Wrap {
                    token_amount: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;

        let master_wallet_wrapped_ata_balance = rpc
            .get_token_account_balance(&master_wallet_wu_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let signer_ata_balance = rpc
            .get_token_account_balance(&signer_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();

        assert_eq!(master_wallet_wrapped_ata_balance, 100 * LAMPORTS_PER_SOL,);
        assert_eq!(signer_ata_balance, 0,);
    }

    println!("Transfering wrapped token");
    {
        // transfer the wrapped token from master_wallet to signer
        let ixs = vec![
            create_associated_token_account(
                &master_wallet.pubkey(), // funding
                &signer.pubkey(),        // owner
                &wu,                     // mint
                &spl_token_2022::ID,
            ),
            transfer_checked(
                &spl_token_2022::ID,
                &master_wallet_wu_ata,
                &wu,
                &signer_wu_ata,
                &master_wallet.pubkey(),
                &[],
                100 * LAMPORTS_PER_SOL,
                9,
            )
            .unwrap(),
        ];

        send_tx(&rpc, ixs, &master_wallet.pubkey(), &[&master_wallet]).await;
    }

    println!("Unwrapping");
    {
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Unwrap {
                    signer: signer.pubkey(),
                    signer_wu_ata,
                    u: u.pubkey(),
                    wu,
                    config_pda,
                    config_pda_u_ata,
                    destination: master_wallet.pubkey(),
                    destination_ata: master_wallet_ata,
                    fee_rebate_reserve_u_ata,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::Unwrap {
                    token_amount: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;

        let signer_wrapped_ata_balance = rpc
            .get_token_account_balance(&signer_wu_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let master_wallet_ata_balance = rpc
            .get_token_account_balance(&master_wallet_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();

        assert_eq!(signer_wrapped_ata_balance, 0,);
        assert_eq!(master_wallet_ata_balance, 100 * LAMPORTS_PER_SOL,);
    }

    println!("MintingAndWrapping");
    {
        let reserves_pda = Pubkey::find_program_address(&[b"reserves"], &oracle_updater::ID).0;

        println!("reserves_account: {:?}", &reserves_pda);
        let mut ixs = vec![];

        // create issuance_wallet_pda_wrapped_ata
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &&issuance_wallet_pda,
            &wu,
            &spl_token_2022::ID,
        ));

        // create company_wallet_wrapped_ata
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &company_wallet.pubkey(),
            &wu,
            &spl_token_2022::ID,
        ));

        // create master_wallet_wrapped_ata
        ixs.push(create_associated_token_account_idempotent(
            &signer.pubkey(),
            &master_wallet.pubkey(),
            &wu,
            &spl_token_2022::ID,
        ));

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::MintAndWrap {
                    signer: signer.pubkey(),
                    config_pda,
                    u: u.pubkey(),
                    wu,
                    issuance_wallet_pda,
                    issuance_wallet_pda_wu_ata,
                    master_wallet: master_wallet.pubkey(),
                    master_wallet_wu_ata,
                    company_wallet: company_wallet.pubkey(),
                    company_wallet_wu_ata,
                    config_pda_u_ata,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                    oracle_updater_program: oracle_updater::ID,
                    reserves_pda,
                })
                .args(wrap_uranium::instruction::MintAndWrap {
                    gross_issue: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        let master_wallet_wrapped_ata_balance = rpc
            .get_token_account_balance(&master_wallet_wu_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let wrapped_supply = rpc
            .get_token_supply(&wu)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        assert_eq!(master_wallet_wrapped_ata_balance, 100 * LAMPORTS_PER_SOL,);
        assert_eq!(wrapped_supply, 100 * LAMPORTS_PER_SOL,);
    }

    println!("Transfering wrapped token");
    {
        // transfer the wrapped token from master wallet to signer
        let ixs = vec![transfer_checked(
            &spl_token_2022::ID,
            &master_wallet_wu_ata,
            &wu,
            &signer_wu_ata,
            &master_wallet.pubkey(),
            &[],
            100 * LAMPORTS_PER_SOL,
            9,
        )
        .unwrap()];

        send_tx(&rpc, ixs, &master_wallet.pubkey(), &[&master_wallet]).await;
    }

    println!("UnwrapAndBurn");
    {
        let mut ixs = vec![];
        // create company
        ixs.push(create_associated_token_account(
            &signer.pubkey(),
            &redemption_wallet_pda,
            &wu,
            &spl_token_2022::ID,
        ));

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::UnwrapAndBurn {
                    signer: signer.pubkey(),
                    signer_wu_ata,
                    config_pda,
                    u: u.pubkey(),
                    config_pda_u_ata,
                    wu,
                    redemption_wallet_pda,
                    redemption_wallet_pda_wu_ata,
                    company_wallet: company_wallet.pubkey(),
                    company_wallet_wu_ata,
                    fee_rebate_reserve_u_ata,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::UnwrapAndBurn {
                    gross_redeem: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        let signer_wrapped_ata_balance = rpc
            .get_token_account_balance(&signer_wu_ata)
            .await
            .unwrap()
            .amount
            .parse::<i64>()
            .unwrap();
        let wrapped_supply = rpc
            .get_token_supply(&wu)
            .await
            .unwrap()
            .amount
            .parse::<i64>()
            .unwrap();
        assert_eq!(signer_wrapped_ata_balance, 0);
        assert_eq!(wrapped_supply, 0);
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
