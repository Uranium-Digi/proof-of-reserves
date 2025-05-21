use access_controller::AccessController;
use access_controller::ID as ACCESS_CONTROLLER_ID;
use solana_program_test::ProgramTestContext;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use std::mem::size_of;
use test_utils::assert::Assert;
use test_utils::base_test_environment::BaseTestSetupBuilder;
use test_utils::client::{AccessControllerClient, VerifierClient};
use verifier::state::VerifierAccount;

pub struct VerifierTestSetup {
    pub environment_context: ProgramTestContext,
    pub user: Keypair,
    pub verifier_client: VerifierClient,
    pub access_controller_client: Option<AccessControllerClient>,
    pub access_controller_account_address: Option<Pubkey>,
    pub verifier_account_address: Pubkey,
}

pub struct VerifierTestSetupBuilder {
    base_builder: BaseTestSetupBuilder,
    program_id: Pubkey,
    account_size: usize,
    access_controller: Pubkey,
    access_controller_is_active: bool,
    init: bool,
}

impl Default for VerifierTestSetupBuilder {
    fn default() -> Self {
        Self {
            base_builder: BaseTestSetupBuilder::new(),
            program_id: Pubkey::default(),
            account_size: size_of::<VerifierAccount>(),
            access_controller: Pubkey::default(),
            access_controller_is_active: true,
            init: true,
        }
    }
}

impl VerifierTestSetupBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn program_name(mut self, name: &'static str) -> Self {
        self.base_builder = self.base_builder.program_name(name);
        self
    }

    pub fn program_id(mut self, id: Pubkey) -> Self {
        self.program_id = id;
        self.base_builder = self.base_builder.program_id(id);
        self
    }

    pub fn account_size(mut self, size: usize) -> Self {
        self.account_size = size;
        self.base_builder = self.base_builder.account_size(size);
        self
    }

    pub fn access_controller(mut self, access_controller: Pubkey) -> Self {
        self.access_controller = access_controller;
        self
    }

    pub fn add_user(mut self, user: Pubkey) -> Self {
        self.base_builder = self.base_builder.add_user(user);
        self
    }

    pub fn add_zero_copy_account(
        mut self,
        program_id: Pubkey,
        account: Pubkey,
        account_size: usize,
        discriminator: Option<[u8; 8]>,
    ) -> Self {
        self.base_builder = self.base_builder.add_zero_copy_account(
            program_id,
            account,
            account_size,
            discriminator,
        );
        self
    }

    pub fn access_controller_active(mut self, is_active: bool) -> Self {
        self.access_controller_is_active = is_active;
        self
    }

    pub fn init(mut self, init: bool) -> Self {
        self.init = init;
        self
    }

    pub fn with_compute_max_units(mut self, max_units: u64) -> Self {
        self.base_builder = self.base_builder.with_compute_max_units(max_units);
        self
    }

    pub async fn build(self) -> VerifierTestSetup {
        let access_controller_account = Pubkey::new_unique();

        let mut base_builder = self
            .base_builder
            .program_id(self.program_id)
            .program_name("verifier")
            .account_size(VerifierAccount::INIT_SPACE); // Deprecated, filled for compatibility

        if self.access_controller_is_active {
            base_builder = base_builder
                .add_program("access_controller", ACCESS_CONTROLLER_ID)
                .add_zero_copy_account(
                    self.access_controller,
                    access_controller_account,
                    size_of::<AccessController>(),
                    None,
                );
        }

        let mut base_setup = base_builder.build().await;

        let access_controller_client = self.access_controller_is_active.then(|| {
            AccessControllerClient::new(self.access_controller, access_controller_account)
        });

        let verifier_client = VerifierClient::new(
            self.program_id,
            self.access_controller_is_active
                .then(|| access_controller_account),
        );

        if self.init {
            if self.access_controller_is_active {
                let mut result = access_controller_client
                    .as_ref()
                    .unwrap()
                    .initialize(&mut base_setup.environment_context, &base_setup.user)
                    .await;
                Assert::transaction_ok(&result);

                result = access_controller_client
                    .as_ref()
                    .unwrap()
                    .add_access(
                        &mut base_setup.environment_context,
                        &base_setup.user,
                        base_setup.user.pubkey(),
                    )
                    .await;
                Assert::transaction_ok(&result);
            }

            let result = verifier_client
                .initialize_realloc_init_data(&mut base_setup.environment_context, &base_setup.user)
                .await;
            Assert::transaction_ok(&result);
        }

        let verifier_account = verifier_client.data_account;

        VerifierTestSetup {
            environment_context: base_setup.environment_context,
            user: base_setup.user,
            verifier_client,
            access_controller_client,
            access_controller_account_address: self
                .access_controller_is_active
                .then_some(access_controller_account),
            verifier_account_address: verifier_account,
        }
    }
}
