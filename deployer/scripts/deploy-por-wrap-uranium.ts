import { exec, execSync } from 'child_process'
import * as fs from 'fs/promises'
import * as path from 'path'
import * as dotenv from 'dotenv'
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js'
import { spitOutWallets } from '../src/convertKey'
import WalletManager, { clearVanityDirectory, generateVanityAddresses } from '../src/WalletManager'
import Common from '../src/Common'
import { TokenFactory } from '../src/TokenFactory'
import { connection, RPC_URL, NETWORK_USED, proofOfReservesProgram, uraniumToken } from '../src/config'
import * as anchor from '@coral-xyz/anchor'
import {
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    getAssociatedTokenAddress,
    getOrCreateAssociatedTokenAccount,
    mintTo,
} from '@solana/spl-token'
import { anchorConnection } from '../src/config'
import MetaplexComplex from '../src/metaplex/metaplexDeployToken'

// Load environment variables
// NOTHING in the env should ever be modified.
dotenv.config({ path: path.resolve(__dirname, '../.env') })

const TOKEN_DEPLOYER_DIR = path.resolve(__dirname, '..')
const PROOF_OF_RESERVES_IDL_DIR = path.resolve(__dirname, '../../target/idl/proof_of_reserves.json')

const metaplexComplex = new MetaplexComplex()

async function writeUraniumTokenAddressToConfig(uraniumTokenAddress: string) {
    // update the token mint in the config.ts file
    const configPath = path.resolve(TOKEN_DEPLOYER_DIR, 'src/config.ts')
    let configContent = await fs.readFile(configPath, 'utf-8')
    configContent = configContent.replace(
        /export const TOKEN_ADDRESS\s*=\s*['"][^'"]+['"]/,
        `export const TOKEN_ADDRESS = '${uraniumTokenAddress.toString()}'`,
    )
    await fs.writeFile(configPath, configContent)
}

async function deployToken(
    config: {
        name: string
        symbol: string
        description: string
        imageUri: string
        initialSupply: number
    },
    vanityAddress?: Keypair,
): Promise<anchor.web3.Keypair> {
    console.log('\n🌟 🌟 🌟 deploying token with Metaplex! 🌟 🌟 🌟\n')

    const vanitAddressToBeUsed = vanityAddress
        ? metaplexComplex.convertAnchorKeypairToUmiKeypairSigner(vanityAddress)
        : undefined

    const tokenMint = await metaplexComplex.createAndMintTokensViaMetaplex({
        name: config.name,
        symbol: config.symbol,
        description: config.description,
        imageUri: config.imageUri,
        initialSupply: BigInt(config.initialSupply * 10 ** 9),
        vanityAddress: vanitAddressToBeUsed,
    })
    await writeUraniumTokenAddressToConfig(tokenMint.publicKey.toString())

    console.log('Token deployed:', tokenMint.publicKey.toString())
    await new Promise((resolve) => setTimeout(resolve, 10000))
    // update the token mint in the config.ts file
    await writeUraniumTokenAddressToConfig(tokenMint.publicKey.toString())
    const tokenMintAnchorKeypair = metaplexComplex.convertUmiKeypairSignerToAnchorKeypair(tokenMint)
    console.log('tokenMintAnchorKeypair:', tokenMintAnchorKeypair)
    return tokenMintAnchorKeypair
}

async function deployProofOfReserves(): Promise<{
    proofOfReservesIdl: any
    proofOfReservesProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 deploying proofOfReserves program! 🌟 🌟 🌟\n')

    execSync('anchor keys list', { stdio: 'inherit' })
    // We will not update the program ID
    console.log('Building program: 👩👩‍🦼 oracle-updater...')
    execSync('anchor build -p proof-of-reserves', { stdio: 'inherit' })
    // sync keys
    execSync('anchor keys sync', { stdio: 'inherit' })
    // build again
    execSync('anchor build -p proof-of-reserves', { stdio: 'inherit' })

    // read the program ID from the build output
    const proofOfReservesIdl = JSON.parse(await fs.readFile(PROOF_OF_RESERVES_IDL_DIR, 'utf-8'))
    const proofOfReservesProgramId = proofOfReservesIdl.address
    console.log('Program ID:', proofOfReservesProgramId)

    // Deploy the oracle updater program
    execSync(`anchor deploy --provider.cluster ${RPC_URL} -p proof-of-reserves`, { stdio: 'inherit' })

    return {
        proofOfReservesIdl,
        proofOfReservesProgramId,
    }
}

export async function initialize(
    tokenAuthority: Keypair,
    fundingWallet: Keypair,
    proofOfReservesIdl: any,
    uraniumTokenAddress: string,
): Promise<{
    u: string
    configPda: string
    proofOfReservesProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 initializing wrapped token with PoR! 🌟 🌟 🌟\n')

    const programProofOfReserves = await proofOfReservesProgram(proofOfReservesIdl)
    const u = await uraniumToken(uraniumTokenAddress)

    console.log('🎭 programProofOfReserves program ID from idl:', programProofOfReserves.programId.toBase58())
    console.log('🪝 Preparing PDAs')

    const [configPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), u.toBuffer()],
        programProofOfReserves.programId,
    )

    console.log('🏦 u :', u.toBase58())
    console.log('🏗️ configPda:', configPda.toBase58())

    const initializeProgramIx = await programProofOfReserves.methods
        .initialize(
            Buffer.from([
                0, 9, 255, 251, 30, 59, 216, 227, 148, 137, 135, 206, 180, 132, 183, 224, 21, 61, 220, 250, 246, 194,
                34, 144, 244, 36, 6, 22, 137, 28, 20, 195,
            ]),
        )
        .accountsPartial({
            signer: tokenAuthority.publicKey,
            u,
            config_pda: configPda,
            token_program: TOKEN_PROGRAM_ID,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: SystemProgram.programId,
        })
        .instruction()

    const transaction = new anchor.web3.Transaction().add(initializeProgramIx)

    try {
        const tx = await anchor.web3.sendAndConfirmTransaction(
            anchorConnection,
            transaction,
            [fundingWallet, tokenAuthority], // fundingWallet first as fee payer, then tokenAuthority as program signer
            {
                commitment: 'confirmed',
            },
        )
        await new Promise((resolve) => setTimeout(resolve, 10000))
        console.log('\n🎉 Transaction successful! 🎉\n Signature:', tx)
        return {
            u: u.toBase58(),
            configPda: configPda.toBase58(),
            proofOfReservesProgramId: programProofOfReserves.programId.toBase58(),
        }
    } catch (e: any) {
        console.error('Transaction failed', e)
        console.log(e.getLogs())
        throw e // Re-throw the error since we can't return valid addresses
    }
}

export async function depositMintAuthority(
    tokenAuthority: Keypair,
    fundingWallet: Keypair,
    proofOfReservesIdl: any,
    uraniumTokenAddress: string,
) {
    console.log('\n🌟 🌟 🌟 depositing mint authority! 🌟 🌟 🌟\n')
    const u = await uraniumToken(uraniumTokenAddress)
    const programProofOfReserves = await proofOfReservesProgram(proofOfReservesIdl)

    const [configPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), u.toBuffer()],
        programProofOfReserves.programId,
    )

    const depositMintAuthorityIx = await programProofOfReserves.methods
        .depositMintAuthority()
        .accountsPartial({
            signer: tokenAuthority.publicKey,
            config: configPDA,
            u: u,
            token_program: TOKEN_PROGRAM_ID,
        })
        .signers([tokenAuthority])
        .instruction()

    const transaction = new anchor.web3.Transaction().add(depositMintAuthorityIx)

    try {
        const tx = await anchor.web3.sendAndConfirmTransaction(
            anchorConnection,
            transaction,
            [fundingWallet, tokenAuthority],
            {
                commitment: 'confirmed',
            },
        )
        console.log('\n🎉 DepositMintAuthority Transaction successful! 🎉\n Signature:', tx)
        await new Promise((resolve) => setTimeout(resolve, 10000))
    } catch (e: any) {
        console.error('DepositMintAuthority failed', e)
        console.log(e.getLogs())
    }
}

async function main(
    {
        deployTokenOnly,
        uraniumTokenAddress,
        useExistingProofOfReservesIdl,
        startsWith,
        endsWith,
        name,
        symbol,
        description,
        imageUri,
        initialSupply,
    }: {
        deployTokenOnly: boolean
        uraniumTokenAddress?: string
        useExistingProofOfReservesIdl?: boolean
        startsWith: string | undefined
        endsWith: string | undefined
        name: string
        symbol: string
        description: string
        imageUri: string
        initialSupply: number
    } = {
        deployTokenOnly: true,
        uraniumTokenAddress: undefined,
        useExistingProofOfReservesIdl: false,
        startsWith: 'WAGA',
        endsWith: 'SHI',
        name: 'Wagashi',
        symbol: 'WAGASHI',
        description: 'This is a Wagashi.',
        imageUri: 'https://raw.githubusercontent.com/Uranium-Digi/lemon-cake/refs/heads/main/namagashi.png',
        initialSupply: 123,
    },
) {
    // Check if we're connected to testnet or devnet
    const endpoint = connection.rpcEndpoint
    console.log('endpoint', endpoint)
    if (!endpoint.includes('testnet') && !endpoint.includes('devnet')) {
        console.error('Error: Not connected to testnet or devnet!')
        console.error(`Current endpoint: ${endpoint}`)

        if (process.env.USE_TESTNET === 'devnet') {
            // Allow devnet
        } else {
            process.exit(1)
        }
    }

    // Show network information
    const network = NETWORK_USED
    if (network !== 'testnet' && network !== 'devnet') {
        console.error('Error: Not connected to testnet or devnet!')
        console.log('network:', network)
        console.error(`Current endpoint: ${endpoint}`)
        process.exit(1)
    }
    console.log('\n=== Deployment Information ===')
    console.log(`Network: ${network}`)
    console.log(`RPC URL: ${endpoint}`)
    console.log('=============================\n')

    let u: PublicKey
    let proofOfReservesIdl: any

    if (!uraniumTokenAddress || deployTokenOnly) {
        await clearVanityDirectory()
        await generateVanityAddresses({
            startsWith,
            endsWith,
            count: 1,
            ignoreCase: true,
        })
        // fetch a vanity address from the .vanity directory
        const vanityAddresses = await fs.readdir(path.resolve(__dirname, '..', '.vanity'))
        console.log('vanityAddresses', vanityAddresses)
        const vanityAddress = vanityAddresses[0]
        console.log('vanityAddress', vanityAddress)
        const vanityKeypair = Keypair.fromSecretKey(
            new Uint8Array(
                JSON.parse(await fs.readFile(path.resolve(__dirname, '..', '.vanity', vanityAddress), 'utf-8')),
            ),
        )
        console.log('vanityKeypair', vanityKeypair)

        const tokenMint = await deployToken(
            {
                name,
                symbol,
                description,
                imageUri,
                initialSupply,
            },
            vanityKeypair,
        )
        u = tokenMint.publicKey
    } else {
        u = new PublicKey(uraniumTokenAddress)
    }
    await writeUraniumTokenAddressToConfig(u.toBase58())

    if (deployTokenOnly) {
        return
    }

    if (useExistingProofOfReservesIdl) {
        proofOfReservesIdl = JSON.parse(await fs.readFile(path.resolve(PROOF_OF_RESERVES_IDL_DIR), 'utf-8'))
        console.log('Using existing proofOfReservesIdl:', proofOfReservesIdl)
    } else {
        const { proofOfReservesIdl: idl_from_new_deployment } = await deployProofOfReserves()
        proofOfReservesIdl = idl_from_new_deployment
        await new Promise((resolve) => setTimeout(resolve, 10000))
    }

    const tokenAuthority = await WalletManager.getTokenAuthority()
    const fundingWallet = await WalletManager.getFundingWallet()

    const { u: uAddress, configPda: configPdaAddress } = await initialize(
        tokenAuthority,
        fundingWallet,
        proofOfReservesIdl,
        u.toBase58(),
    )

    await depositMintAuthority(tokenAuthority, fundingWallet, proofOfReservesIdl, u.toBase58())

    // Save addresses to file
    await saveAddressesToFile({
        u: uAddress,
        configPda: configPdaAddress,
        proofOfReservesProgramId: proofOfReservesIdl.address,
    })
}

async function saveAddressesToFile(addresses: { u: string; configPda: string; proofOfReservesProgramId: string }) {
    const addressesPath = path.resolve(TOKEN_DEPLOYER_DIR, 'deployed-addresses.json')
    const timestamp = new Date().toISOString()
    const data = {
        timestamp,
        network: NETWORK_USED,
        addresses,
    }
    await fs.writeFile(addressesPath, JSON.stringify(data, null, 2))
    console.log('\n📝 Addresses saved to:', addressesPath)
}

main({
    deployTokenOnly: false,
    uraniumTokenAddress: 'WaGavLAFHcb9RrpfqkVgUBsJr5A6myEZGB5SyihR2bv',
    useExistingProofOfReservesIdl: true,
    startsWith: 'WAGA', // startsWith: 'WAGA',
    endsWith: undefined, // endsWith: '1',
    name: 'Wagashi',
    symbol: 'WAGASHI',
    description: 'This is a Wagashi.',
    imageUri: 'https://raw.githubusercontent.com/Uranium-Digi/lemon-cake/refs/heads/main/namagashi.png',
    initialSupply: 0,
})

// async function generateVanity() {
//     const vanityAddresses = await generateVanityAddresses({
//         startsWith: 'cake',
//         count: 7,
//         ignoreCase: true,
//     })
// }
