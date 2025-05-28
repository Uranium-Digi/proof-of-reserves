# Deployment Pipeline

This document outlines the complete pipeline for deploying the Uranium token and its wrapper contract.

## Prerequisites

- Solana CLI tools installed
- Anchor framework installed
- Node.js and Yarn installed
- Sufficient SOL in wallet for deployment

## Important Notes

1. The wallet that deploys the base token MUST be the same wallet that deploys the wrap-uranium contract. This is critical because:

    - The wrap-uranium contract needs to be able to mint wrapped tokens
    - The contract needs to be able to burn wrapped tokens
    - The contract needs to be able to manage the base token's mint_ata

2. The token authority (which controls taxation) can be:

    - Initially set to the deployment wallet
    - Later transferred to a multisig wallet using the token's transfer authority function

3. Program ID Handling:
    - The program ID in the code is a placeholder
    - Anchor will automatically update the program ID during deployment
    - The same program ID can be used across different networks
    - No manual program ID updates are required

## Deployment Steps

### 1. Update Submodule

```bash
# Update the wrap-uranium submodule to latest commit
git submodule update --init --recursive
git submodule update --remote
```

### 2. Deploy Base Token

```bash
# Create a new keypair for the mint
solana-keygen new -o .secrets/mint-keypair.json

# Get the mint address
MINT_ADDRESS=$(solana-keygen pubkey .secrets/mint-keypair.json)

# Deploy the token using TokenFactory
yarn ts-node scripts/deploy-token.ts
```

### 3. Deploy Wrap-Uranium Contract

```bash
# Navigate to wrap-uranium directory
cd submodules/wrap-uranium

# Copy the deployment wallet to wrap-uranium's Anchor.toml
cp ../.secrets/funding-wallet.json wallet.json

# Build the program
anchor build

# Deploy to target network (using the same wallet as token deployment)
anchor deploy

# Get the program ID
PROGRAM_ID=$(solana-keygen pubkey ./target/deploy/wrap_uranium-keypair.json)

# Return to token-deployer directory
cd ../..
```

### 4. Initialize Wrap-Uranium Contract

```bash
# Build the program
yarn build

# Initialize the wrap-uranium contract
yarn ts-node scripts/initialize-wrapper.ts
```

## Directory Structure

```
token-deployer/
├── .secrets/
│   ├── funding-wallet.json
│   ├── token-authority.json
│   └── mint-keypair.json
├── submodules/
│   └── wrap-uranium/
│       ├── target/
│       │   └── deploy/
│       │       └── wrap_uranium-keypair.json
│       └── programs/
│           └── wrap-uranium/
└── scripts/
    ├── deploy-token.ts
    └── initialize-wrapper.ts
```

## Environment Variables

Required environment variables in `.env`:

```
RPC_URL=https://api.devnet.solana.com
DEPLOYMENT_WALLET_PATH=.secrets/funding-wallet.json
TOKEN_AUTHORITY_PATH=.secrets/token-authority.json
SPL_TOKEN_ADDRESS=<mint-address>
WRAP_URANIUM_PROGRAM_ID=<program-id>
```

## Future Improvements

1. Direct access to wrap-uranium's target folder instead of copying files
2. Integration with multisig wallet for token authority
3. Automated testing after deployment
4. Network-specific deployment configurations

# Manual Deployment Guide

This guide provides the manual CLI commands equivalent to the automated deployment script.

## Prerequisites

- Solana CLI tools installed
- Anchor CLI installed
- Node.js and npm/yarn installed
- Environment variables set in `.env` file

## 1. Deploy Token

```bash
# Convert private keys to JSON wallets
node -e "require('./src/convertKey').spitOutWallets()"

# Deploy token using TokenFactory
npx ts-node -e "
  const { WalletManager } = require('./src/WalletManager');
  const Common = require('./src/Common');
  const { TokenFactory } = require('./src/TokenFactory');
  const { connection } = require('./src/config');

  async function deploy() {
    const fundingWallet = await WalletManager.getFundingWallet();
    const common = new Common(connection, fundingWallet);
    const tokenFactory = new TokenFactory(common);
    const tokenMint = await tokenFactory.deployToken('Token', 'T', '', 'This is a token implementation', false, 1);
    console.log('Token deployed:', tokenMint.toString());
    return tokenMint;
  }

  deploy();
"
```

## 2. Deploy Wrapped Token Program

```bash
# Update git submodule
git submodule update --init --recursive

# Navigate to wrap-uranium directory
cd submodules/wrap-uranium

# Clean previous build artifacts
rm -rf target/deploy/*

# Generate new program ID
solana-keygen new --no-passphrase --outfile target/deploy/wrap_uranium-keypair.json
PROGRAM_ID=$(solana address -k target/deploy/wrap_uranium-keypair.json)

# Update Anchor.toml with new program ID and wallet
sed -i '' "s/wrap_uranium = \".*\"/wrap_uranium = \"$PROGRAM_ID\"/" Anchor.toml
sed -i '' "s|wallet = \".*\"|wallet = \"$TOKEN_AUTHORITY_PATH\"|" Anchor.toml

# Update lib.rs with new program ID
sed -i '' "s/declare_id!(\".*\")/declare_id!(\"$PROGRAM_ID\")/" programs/wrap-uranium/src/lib.rs

# Build and deploy
anchor build
anchor deploy

# Return to main directory
cd ../..
```

## 3. Update Configuration

```bash
# Update program ID in config.ts
sed -i '' "s/WRAP_TOKEN_PROGRAM_ID = '.*'/WRAP_TOKEN_PROGRAM_ID = '$PROGRAM_ID'/" src/config.ts
```

## 4. Initialize Wrapped Token

```bash
# Initialize wrapped token with the deployed token mint
npx ts-node -e "
  const { initializeWrappedToken } = require('./src/wrapper/initialize');
  initializeWrappedToken('$TOKEN_MINT');
"
```

## Environment Variables

Make sure these environment variables are set in your `.env` file:

```
TOKEN_AUTHORITY_PATH=.secrets/tokenAuthority.json
TESTNET_PUBLIC_RPC_URL=https://api.testnet.solana.com
```

## Notes

- Replace `$TOKEN_MINT` with the actual token mint address from step 1
- Replace `$TOKEN_AUTHORITY_PATH` with the absolute path to your token authority wallet
- The `sed` commands are for macOS. For Linux, remove the empty quotes after `-i`
- Make sure you're connected to testnet before deploying
