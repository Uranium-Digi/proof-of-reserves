import { describe, expect, beforeAll, it } from '@jest/globals'
import { Keypair, PublicKey } from '@solana/web3.js'
import { connection } from '../src/config'
import Common from '../src/Common'
import { TokenDeployer } from '../src/TokenDeployer'
import WalletManager from '../src/WalletManager'
import * as dotenv from 'dotenv'
import path from 'path'

// Load test environment variables
dotenv.config({ path: path.resolve(__dirname, '../.env') })

describe('Token Deployment', () => {
    let tokenDeployer: TokenDeployer
    let common: Common
    let fundingWallet: Keypair
    let tokenAuthority: Keypair

    beforeAll(async () => {
        // Load wallets using WalletManager
        fundingWallet = await WalletManager.getFundingWallet()
        tokenAuthority = await WalletManager.getTokenAuthority()

        // Initialize Common
        common = new Common(connection, fundingWallet)

        // Initialize TokenDeployer
        tokenDeployer = new TokenDeployer(common)
    })

    it('should have valid wallet balances', async () => {
        // Check funding wallet balance
        const fundingBalance = await connection.getBalance(fundingWallet.publicKey)
        expect(fundingBalance).toBeGreaterThan(0)
        console.log('Funding wallet balance:', fundingBalance / 1e9, 'SOL')
        console.log('Funding wallet address:', fundingWallet.publicKey.toBase58())

        // Check token authority balance
        const tokenAuthorityBalance = await connection.getBalance(tokenAuthority.publicKey)
        expect(tokenAuthorityBalance).toBeGreaterThan(0)
        console.log('Token authority balance:', tokenAuthorityBalance / 1e9, 'SOL')
        console.log('Token authority address:', tokenAuthority.publicKey.toBase58())
    })

    it('should deploy a new token', async () => {
        const tokenConfig = {
            name: 'Test Token',
            symbol: 'TEST',
            uri: 'https://test.com/metadata.json',
            decimals: 9,
            initialSupply: BigInt(1000000000),
            feeConfig: {
                feeBasisPoints: 0,
                maxFee: BigInt(100_000_000_000 * 1e9),
            },
        }

        const mintAddress = await tokenDeployer.deployToken(tokenConfig)
        expect(mintAddress).toBeDefined()
        expect(mintAddress).toBeInstanceOf(PublicKey)
        expect(mintAddress.toBase58()).toBeTruthy()
    })
})
