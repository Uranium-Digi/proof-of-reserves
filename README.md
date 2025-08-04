**Update the `INIT_AUTHORITY` in `programs/proof-of-reserves/src/lib.rs` before deploying**

To deploy the proof of reserves program
```bash
anchor deploy  --provider.cluster devnet
```

To run the transmitter
`cargo run --bin transmitter`


### Roles
#### Init Authority

The hardcoded INIT_AUTHORITY is a temporary, one-time authority used solely to initialize the program.

#### Authority

The primary authority of the program. Responsible for setting other authorities, configuring issuance and redemption fees, and updating the feedId.

#### Issue Authority

Authorized to issue new tokens.
#### Redeem Authority

Authorized to redeem existing tokens.
#### Update Authority

Held by the transmitter. Responsible for verifying reports and updating the reserve amount.
