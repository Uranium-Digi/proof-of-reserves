use std::str::FromStr;

use anchor_client::{
    anchor_lang::solana_program,
    solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signer::Signer},
    Client, Cluster,
};

use anchor_spl::{
    associated_token::spl_associated_token_account::{
        self, get_associated_token_address_with_program_id,
        instruction::create_associated_token_account,
    },
    token_2022::spl_token_2022::{self, instruction::transfer_checked},
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    message::{v0::Message, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    signature::{read_keypair_file, Keypair, Signature},
    signers::Signers,
    system_instruction::create_account,
    transaction::VersionedTransaction,
};

use transmitter::transmitter::transmitter::Transmitter;
use verifier::state::VerifierAccount;

use crate::common::verifier_test_setup::{VerifierTestSetup, VerifierTestSetupBuilder};

#[tokio::test]
// #[test]
async fn test_initialize() {
    let VerifierTestSetup {
        mut environment_context,
        verifier_client,
        access_controller_account_address,
        ..
    } = VerifierTestSetupBuilder::new()
        .program_name("verifier")
        .program_id(verifier::ID)
        .access_controller(access_controller::ID)
        .build()
        .await;

    // Load the verifier account state and deserialize it
    let verifier_account: VerifierAccount = verifier_client
        .read_verifier_account(&mut environment_context)
        .await
        .unwrap();

    // Check the contract account state matches that passed within the instruction
    assert_eq!(
        access_controller_account_address.unwrap(),
        verifier_account.verifier_account_config.access_controller
    );

    let program_id = Pubkey::from_str("3JmfgAqnGnyh8pXGo8w8bi6MGjfd3Jn4aaKqfJgb7UcQ").unwrap();

    // let oracle_updater_id;
    let transmitter =
        Transmitter::new(Some(Cluster::Localnet), Some("ANCHOR_WALLET".to_string())).unwrap();

    let anchor_wallet = std::env::var("ANCHOR_WALLET").unwrap();
    println!("Anchor wallet: {}", anchor_wallet);
    let signer = read_keypair_file(&anchor_wallet).unwrap();
    let owner = Keypair::new();
    let dest = Keypair::new();
    let mint = Keypair::new();

    let client =
        Client::new_with_options(Cluster::Localnet, &signer, CommitmentConfig::processed());

    let program = client.program(program_id).unwrap();
    let rpc = program.rpc();

    rpc.request_airdrop(&signer.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    rpc.request_airdrop(&dest.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    rpc.request_airdrop(&owner.pubkey(), 5 * LAMPORTS_PER_SOL)
        .await
        .unwrap();

    let wrapped_mint =
        Pubkey::find_program_address(&[b"wrapped_mint", mint.pubkey().as_ref()], &program_id).0;

    let config = Pubkey::find_program_address(&[b"config2", mint.pubkey().as_ref()], &program_id).0;

    let fee_rebate_reserve = Pubkey::find_program_address(
        &[b"fee_rebate_reserve", mint.pubkey().as_ref()],
        &program_id,
    )
    .0;

    let mint_ata = get_associated_token_address_with_program_id(
        &config,        // owner
        &mint.pubkey(), // mint
        &spl_token_2022::ID,
    );

    let dest_wrapped_ata = get_associated_token_address_with_program_id(
        &dest.pubkey(),
        &wrapped_mint,
        &spl_token_2022::ID,
    );

    let destination_ata = get_associated_token_address_with_program_id(
        &dest.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::ID,
    );

    let owner_ata = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::ID,
    );

    let owner_wrapped_ata = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        &wrapped_mint,
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
                &mint.pubkey(),
                rent,
                space as u64,
                &spl_token_2022::ID,
            ),
            // Init mint with transfer fee
            spl_token_2022::extension::transfer_fee::instruction::initialize_transfer_fee_config(
                &spl_token_2022::ID,
                &mint.pubkey(),
                Some(&signer.pubkey()),   // Transfer fee authority
                Some(&signer.pubkey()),   // Withdraw withheld fee authority
                1000,                     // Fee bps
                10000 * LAMPORTS_PER_SOL, // Max fee
            )
            .unwrap(),
            spl_token_2022::instruction::initialize_mint(
                &spl_token_2022::ID,
                &mint.pubkey(),   // Mint address
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
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::Initialize {})
                .instructions()
                .unwrap(),
        );

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Initialize2 {
                    signer: signer.pubkey(),
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    mint_ata,
                    fee_rebate_reserve,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::Initialize2 {})
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &mint]).await;
    }

    println!("Minting to fee rebate reserve");
    {
        let mut ixs = vec![];

        ixs.push(
            spl_token_2022::instruction::mint_to(
                &spl_token_2022::ID,
                &mint.pubkey(),
                &fee_rebate_reserve,
                &signer.pubkey(),
                &[],
                1_000_000 * LAMPORTS_PER_SOL,
            )
            .unwrap(),
        );
        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
    }

    println!("Wrapping");
    {
        let mut ixs = vec![
            create_associated_token_account(
                &signer.pubkey(),
                &owner.pubkey(),
                &mint.pubkey(),
                &spl_token_2022::ID,
            ),
            spl_token_2022::instruction::mint_to(
                &spl_token_2022::ID,
                &mint.pubkey(),
                &owner_ata,
                &signer.pubkey(),
                &[],
                100 * LAMPORTS_PER_SOL,
            )
            .unwrap(),
        ];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Wrap {
                    signer: signer.pubkey(),
                    owner: owner.pubkey(),
                    owner_ata,
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    mint_ata,
                    destination: dest.pubkey(),
                    destination_wrapped_ata: dest_wrapped_ata,
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

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &owner]).await;

        let dest_wrapped_ata_balance = rpc
            .get_token_account_balance(&dest_wrapped_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let owner_ata_balance = rpc
            .get_token_account_balance(&owner_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();

        assert_eq!(dest_wrapped_ata_balance, 100 * LAMPORTS_PER_SOL,);
        assert_eq!(owner_ata_balance, 0,);
    }

    println!("Transfering wrapped token");
    {
        // transfer the wrapped token from destination to owner
        let ixs = vec![
            create_associated_token_account(
                &dest.pubkey(),
                &owner.pubkey(),
                &wrapped_mint,
                &spl_token_2022::ID,
            ),
            transfer_checked(
                &spl_token_2022::ID,
                &dest_wrapped_ata,
                &wrapped_mint,
                &owner_wrapped_ata,
                &dest.pubkey(),
                &[],
                100 * LAMPORTS_PER_SOL,
                9,
            )
            .unwrap(),
        ];

        send_tx(&rpc, ixs, &dest.pubkey(), &[&dest]).await;
    }

    println!("Unwrapping");
    {
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::Unwrap {
                    signer: signer.pubkey(),
                    owner: owner.pubkey(),
                    owner_wrapped_ata,
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    mint_ata,
                    destination: dest.pubkey(),
                    destination_ata,
                    fee_rebate_reserve,
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

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &owner]).await;

        let owner_wrapped_ata_balance = rpc
            .get_token_account_balance(&owner_wrapped_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let destination_ata_balance = rpc
            .get_token_account_balance(&destination_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();

        assert_eq!(owner_wrapped_ata_balance, 0,);
        assert_eq!(destination_ata_balance, 100 * LAMPORTS_PER_SOL,);
    }

    println!("MintingAndWrapping");
    {
        let mintable_account =
            Pubkey::find_program_address(&[b"mintable_account"], &oracle_updater::ID).0;
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::MintAndWrap {
                    signer: signer.pubkey(),
                    mint_authority: signer.pubkey(),
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    mint_ata,
                    token_program: spl_token_2022::ID,
                    destination_wrapped_ata: dest_wrapped_ata,
                    destination: dest.pubkey(),
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                    //
                    oracle_updater_program: oracle_updater::ID,
                    mintable_account,
                })
                .args(wrap_uranium::instruction::MintAndWrap {
                    token_amount: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer]).await;
        let dest_wrapped_ata_balance = rpc
            .get_token_account_balance(&dest_wrapped_ata)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        let wrapped_supply = rpc
            .get_token_supply(&wrapped_mint)
            .await
            .unwrap()
            .amount
            .parse::<u64>()
            .unwrap();
        assert_eq!(dest_wrapped_ata_balance, 100 * LAMPORTS_PER_SOL,);
        assert_eq!(wrapped_supply, 100 * LAMPORTS_PER_SOL,);
    }

    println!("Transfering wrapped token");
    {
        // transfer the wrapped token from destination to signer
        let ixs = vec![transfer_checked(
            &spl_token_2022::ID,
            &dest_wrapped_ata,
            &wrapped_mint,
            &owner_wrapped_ata,
            &dest.pubkey(),
            &[],
            100 * LAMPORTS_PER_SOL,
            9,
        )
        .unwrap()];

        send_tx(&rpc, ixs, &dest.pubkey(), &[&dest]).await;
    }

    println!("UnwrapAndBurn");
    {
        pub const DEFAULT_HEX_STRING: &str = "0x00064f2cd1be62b7496ad4897b984db99243e0921906f66ded15149d993ef42c000000000000000000000000000000000000000000000000000000000103c90c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200003684ea93c43ed7bd00ab3bb189bb62f880436589f1ca58b599cd97d6007fb0000000000000000000000000000000000000000000000000000000067570fa40000000000000000000000000000000000000000000000000000000067570fa400000000000000000000000000000000000000000000000000004c6ac85bf854000000000000000000000000000000000000000000000000002e1bf13b772a9c0000000000000000000000000000000000000000000000000000000067586124000000000000000000000000000000000000000000000000002bb4cf7662949c000000000000000000000000000000000000000000000000002bae04e2661000000000000000000000000000000000000000000000000000002bb6a26c3fbeb80000000000000000000000000000000000000000000000000000000000000002af5e1b45dd8c84b12b4b58651ff4173ad7ca3f5d7f5374f077f71cce020fca787124749ce727634833d6ca67724fd912535c5da0f42fa525f46942492458f2c2000000000000000000000000000000000000000000000000000000000000000204e0bfa6e82373ae7dff01a305b72f1debe0b1f942a3af01bad18e0dc78a599f10bc40c2474b4059d43a591b75bdfdd80aafeffddfd66d0395cca2fdeba1673d";
        let full_report = DEFAULT_HEX_STRING;
        transmitter.verify(full_report).await.unwrap();
        let mut ixs = vec![];

        ixs.append(
            &mut program
                .request()
                .accounts(wrap_uranium::accounts::UnwrapAndBurn {
                    signer: signer.pubkey(),
                    owner: owner.pubkey(),
                    mint: mint.pubkey(),
                    wrapped_mint,
                    config,
                    mint_ata,
                    owner_wrapped_ata,
                    fee_rebate_reserve,
                    token_program: spl_token_2022::ID,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: solana_program::system_program::ID,
                })
                .args(wrap_uranium::instruction::UnwrapAndBurn {
                    token_amount: 100 * LAMPORTS_PER_SOL,
                })
                .instructions()
                .unwrap(),
        );

        send_tx(&rpc, ixs, &signer.pubkey(), &[&signer, &owner]).await;
        let owner_wrapped_ata_balance = rpc
            .get_token_account_balance(&owner_wrapped_ata)
            .await
            .unwrap()
            .amount
            .parse::<i64>()
            .unwrap();
        let wrapped_supply = rpc
            .get_token_supply(&wrapped_mint)
            .await
            .unwrap()
            .amount
            .parse::<i64>()
            .unwrap();
        assert_eq!(owner_wrapped_ata_balance, 0);
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
