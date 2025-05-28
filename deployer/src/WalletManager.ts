import fs from 'fs/promises'
import path from 'path'

import { DIRECTORIES } from './config'

import { Keypair, PublicKey } from '@solana/web3.js'

export default class WalletManager {
    constructor() {}

    private static async loadWalletFromFile(envPath: string): Promise<Keypair> {
        try {
            const filePath = path.join(process.cwd(), envPath)
            const secretKey = JSON.parse(await fs.readFile(filePath, 'utf-8'))
            const wallet = Keypair.fromSecretKey(new Uint8Array(secretKey))
            console.info(`Wallet loaded: ${wallet.publicKey.toBase58()}`)
            return wallet
        } catch (err) {
            console.error(`Failed to load wallet from path: ${envPath}`, err)
            throw new Error(`Failed to load wallet from path: ${envPath}`)
        }
    }

    static async getFundingWallet(): Promise<Keypair> {
        const walletPath = DIRECTORIES.FUNDING_WALLET_FILE

        if (!walletPath) {
            throw new Error('FUNDING_WALLET_PATH not specified in environment variables')
        }
        return this.loadWalletFromFile(walletPath)
    }

    static async getTokenAuthority(): Promise<Keypair> {
        const walletPath = DIRECTORIES.TOKEN_AUTHORITY_FILE

        if (!walletPath) {
            throw new Error('TOKEN_AUTHORITY_PATH not specified in environment variables')
        }
        return this.loadWalletFromFile(walletPath)
    }
}
