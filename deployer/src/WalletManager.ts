import * as path from 'path'
import fs from 'fs/promises'

import { DIRECTORIES } from './config'
const { execSync } = require('child_process')
import { Keypair, PublicKey } from '@solana/web3.js'
import { createSignerFromKeypair, KeypairSigner, signerIdentity } from '@metaplex-foundation/umi'

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
    // static async getFundingWalletUmi(): Promise<KeypairSigner> {
    //     // https://developers.metaplex.com/umi/getting-started#connecting-a-wallet
    //     const walletPath = DIRECTORIES.FUNDING_WALLET_FILE
    //     const filePath = path.join(process.cwd(), walletPath)
    //     const secretKey = JSON.parse(await fs.readFile(filePath, 'utf-8'))

    //     let keypair = umi.eddsa.createKeypairFromSecretKey(new Uint8Array(secretKey))
    //     const signer = createSignerFromKeypair(umi, keypair)

    //     return signer
    // }
}

interface VanityOptions {
    startsWith?: string
    endsWith?: string
    startsAndEndsWith?: { prefix: string; suffix: string }
    count: number
    ignoreCase?: boolean
}

export const clearVanityDirectory = async () => {
    const vanityDir = path.resolve(__dirname, '..', '.vanity')
    await fs.rm(vanityDir, { recursive: true })
}

export const generateVanityAddresses = async (options: VanityOptions) => {
    const vanityDir = path.resolve(__dirname, '..', '.vanity')
    await fs.mkdir(vanityDir, { recursive: true })

    console.log('vanityDir', vanityDir)

    let command = 'solana-keygen grind'

    // Add required count parameter
    if (options.startsWith) {
        command += ` --starts-with ${options.startsWith}:${options.count}`
    } else if (options.endsWith) {
        command += ` --ends-with ${options.endsWith}:${options.count}`
    } else if (options.startsAndEndsWith) {
        command += ` --starts-and-ends-with ${options.startsAndEndsWith.prefix}:${options.startsAndEndsWith.suffix}:${options.count}`
    } else {
        throw new Error('Must specify either startsWith, endsWith, or startsAndEndsWith')
    }

    // Add optional parameters
    if (options.ignoreCase) command += ' --ignore-case'

    console.log(`Running command: ${command}`)
    const addresses: Keypair[] = []
    const output = execSync(command, {
        encoding: 'utf-8',
        cwd: vanityDir,
    })
}
