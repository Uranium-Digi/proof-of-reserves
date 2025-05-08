use {
    crate::verifier::loader::Verifier,
    crate::wallet_loader::load_funding_wallet,
    anchor_client::{
        Client, Cluster,
        solana_client::rpc_client::RpcClient,
        solana_sdk::{
            commitment_config::CommitmentConfig,
            native_token::LAMPORTS_PER_SOL,
            signature::{Keypair, read_keypair_file},
            signer::Signer,
            system_program,
        },
    },
    anchor_lang::prelude::*,
    anyhow::Result,
    oracle_updater::ID as ORACLE_UPDATER_ID,
    std::rc::Rc,
};

pub struct Transmitter {
    rpc_client: RpcClient,
    wallet: Rc<Keypair>,
    // oracle_updater: OracleUpdaterProgram,
}

impl Transmitter {
    pub fn new(rpc_url: &str, commitment: CommitmentConfig) -> Result<Self> {
        let rpc_client = RpcClient::new_with_commitment(rpc_url.to_string(), commitment);
        let wallet = load_funding_wallet()?;

        println!("🔑 Loaded wallet pubkey: {}", wallet.pubkey());

        Ok(Self { rpc_client, wallet })
    }

    // pub fn verify_report(
    //     &self,
    //     verifier_account: Pubkey,
    //     access_controller: Pubkey,
    //     config_account: Pubkey,
    //     verifier_program_id: Pubkey,
    //     signed_report: Vec<u8>,
    // ) -> Result<()> {
    //     self.oracle_updater.verify(
    //         verifier_account,
    //         access_controller,
    //         self.wallet.pubkey(),
    //         config_account,
    //         verifier_program_id,
    //         signed_report,
    //     )
    // }
}

#[tokio::main]
async fn transmit() -> anyhow::Result<()> {
    // let connection = RpcClient::new_with_commitment(
    //     "http://127.0.0.1:8899", // Local validator URL
    //     CommitmentConfig::confirmed(),
    // );

    // // Generate Keypairs and request airdrop
    // let payer = Keypair::new();
    // let counter = Keypair::new();
    // println!("Generated Keypairs:");
    // println!("   Payer: {}", payer.pubkey());
    // println!("   Counter: {}", counter.pubkey());

    // println!("\nRequesting 1 SOL airdrop to payer");
    // let airdrop_signature = connection.request_airdrop(&payer.pubkey(), LAMPORTS_PER_SOL)?;

    // // Wait for airdrop confirmation
    // while !connection.confirm_transaction(&airdrop_signature)? {
    //     std::thread::sleep(std::time::Duration::from_millis(100));
    // }
    // println!("   Airdrop confirmed!");

    // // Create program client
    // let provider = Client::new_with_options(
    //     Cluster::Localnet,
    //     Rc::new(payer),
    //     CommitmentConfig::confirmed(),
    // );
    // let program = provider.program(ORACLE_UPDATER_ID)?;

    // // Build and send instructions
    // println!("\nSend transaction with initialize and increment instructions");
    // let initialize_ix = program
    //     .request()
    //     .accounts(accounts::Initialize {
    //         counter: counter.pubkey(),
    //         payer: program.payer(),
    //         system_program: system_program::ID,
    //     })
    //     .args(args::Initialize)
    //     .instructions()?
    //     .remove(0);

    // let increment_ix = program
    //     .request()
    //     .accounts(accounts::Increment {
    //         counter: counter.pubkey(),
    //     })
    //     .args(args::Increment)
    //     .instructions()?
    //     .remove(0);

    // let signature = program
    //     .request()
    //     .instruction(initialize_ix)
    //     .instruction(increment_ix)
    //     .signer(&counter)
    //     .send()
    //     .await?;
    // println!("   Transaction confirmed: {}", signature);

    // println!("\nFetch counter account data");
    // let counter_account: Counter = program.account::<Counter>(counter.pubkey()).await?;
    // println!("   Counter value: {}", counter_account.count);
    Ok(())
}
