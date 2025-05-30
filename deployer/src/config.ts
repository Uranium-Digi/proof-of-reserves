import path from 'path'
import { Connection, PublicKey } from '@solana/web3.js'
import * as dotenv from 'dotenv'
import * as anchor from '@coral-xyz/anchor'
import WalletManager from './WalletManager'

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') })

// Program IDs
export const WRAP_TOKEN_PROGRAM_ID = 'HbMJgorqybuweCMEeXXg5HqPBAzLCfqiMEpqGrR2Dc9r'
export const TOKEN_ADDRESS = '4FjZ9mf2UF79ip26m2TnQSuEeuwUP8Kui7dFs7ZEhvnM'

// Connection
export const NETWORK_USED: string = process.env.NETWORK_USED || 'devnet'
// export const NETWORK_USED: string = 'devnet' // 'testnet' | 'mainnet' | 'devnet'

export const RPC_URL =
    NETWORK_USED === 'testnet'
        ? process.env.TESTNET_PUBLIC_RPC_URL || 'https://api.testnet.solana.com'
        : NETWORK_USED === 'devnet'
          ? process.env.DEVNET_PUBLIC_RPC_URL || process.env.DEVNET_RPC_URL || 'https://api.devnet.solana.com'
          : NETWORK_USED === 'mainnet'
            ? process.env.MAINNET_PUBLIC_RPC_URL || 'https://api.mainnet-beta.solana.com'
            : 'https://api.devnet.solana.com' // use devnet as fallback

export const connection = new Connection(RPC_URL, 'confirmed')
export const anchorConnection = new anchor.web3.Connection(RPC_URL)

// Directory paths
export const DIRECTORIES = {
    FUNDING_WALLET_FILE: process.env.FUNDING_WALLET_FILE_FOR_DEPLOYER || '',
    TOKEN_AUTHORITY_FILE: process.env.TOKEN_AUTHORITY_PATH_FOR_DEPLOYER || '',
}

export const setUpAnchorProvider = async () => {
    const tokenAuthority = await WalletManager.getTokenAuthority()
    const wallet = new anchor.Wallet(tokenAuthority)

    console.log('☕️ Setting provider and program...')

    const provider = new anchor.AnchorProvider(anchorConnection, wallet, {})
    anchor.setProvider(provider)
    return provider
}
export const wrapUraniumProgram = async (wrapUraniumIDL: any): Promise<anchor.Program> => {
    const provider = await setUpAnchorProvider()
    const programWrapUranium = new anchor.Program(wrapUraniumIDL as any, provider)
    return programWrapUranium
}

export const uraniumToken = async (uraniumTokenAddress: string) => {
    const mint = new anchor.web3.PublicKey(uraniumTokenAddress)
    return mint
}
