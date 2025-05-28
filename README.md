run `cargo test test_proof_state_encoding_decoding -- --nocapture` in `oracle-updater/programs/oracle-updater` directory to test individually.

To deploy the oracle-updater
`anchor deploy -p oracle-updater --provider.cluster devnet`

To run the transmitter
`cargo run --bin transmitter`
