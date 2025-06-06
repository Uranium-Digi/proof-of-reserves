import path from 'path'
import { Connection, PublicKey } from '@solana/web3.js'
import * as dotenv from 'dotenv'
import * as anchor from '@coral-xyz/anchor'
import * as fs from 'fs'
import WalletManager from './WalletManager'
import { createUmi } from '@metaplex-foundation/umi-bundle-defaults'
import { mplTokenMetadata } from '@metaplex-foundation/mpl-token-metadata'
import { createSignerFromKeypair, signerIdentity } from '@metaplex-foundation/umi'
import { irysUploader } from '@metaplex-foundation/umi-uploader-irys'

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') })

// Program IDs
export const WRAP_TOKEN_PROGRAM_ID = '2kg6WJrBjEhqPyWPdx3ct2KovhWD3hGoAihhwNo4XigW'
export const TOKEN_ADDRESS = 'CAKE1GCTDnRg6zb7zyzLu69HxkW8ZJBt9Fx8ENGSS8KF'

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

export const setUpUmi = () => {
    console.log('Setting up UMI: RPC_URL', RPC_URL)
    // https://developers.metaplex.com/umi/getting-started#connecting-a-wallet
    const umi = createUmi(RPC_URL).use(mplTokenMetadata()).use(irysUploader())

    const tokenAuthorityPath = DIRECTORIES.TOKEN_AUTHORITY_FILE
    const filePath = path.join(process.cwd(), tokenAuthorityPath)
    const fileContent = fs.readFileSync(filePath, 'utf-8')
    const secretKey = JSON.parse(fileContent)
    let keypair = umi.eddsa.createKeypairFromSecretKey(new Uint8Array(secretKey))
    const signer = createSignerFromKeypair(umi, keypair)
    umi.use(signerIdentity(signer))
    return umi
}

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
export const proofOfReservesProgram = async (proofOfReservesIdl: any): Promise<anchor.Program> => {
    const provider = await setUpAnchorProvider()
    const programProofOfReserves = new anchor.Program(proofOfReservesIdl as any, provider)
    return programProofOfReserves
}

export const uraniumToken = async (uraniumTokenAddress: string) => {
    const mint = new anchor.web3.PublicKey(uraniumTokenAddress)
    return mint
}
