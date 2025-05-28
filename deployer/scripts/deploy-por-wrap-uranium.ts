import { exec, execSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import * as dotenv from 'dotenv'
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js'
import { spitOutWallets } from '../src/convertKey'
import WalletManager from '../src/WalletManager'
import Common from '../src/Common'
import { TokenFactory } from '../src/TokenFactory'
import { connection, RPC_URL, NETWORK_USED } from '../src/config'
import * as anchor from '@coral-xyz/anchor'
import { TOKEN_2022_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '@solana/spl-token'
import { ExtensionType, getMintLen } from '@solana/spl-token'
import { readFile } from 'fs/promises'
import { anchorConnection } from '../src/config'

// Load environment variables
// NOTHING in the env should ever be modified.
dotenv.config({ path: path.resolve(__dirname, '../.env') })

const TOKEN_DEPLOYER_DIR = path.resolve(__dirname, '..')
const ORACLE_UPDATER_IDL_DIR = path.resolve(__dirname, '../../target/idl/oracle_updater.json')
const WRAP_URANIUM_IDL_DIR = path.resolve(__dirname, '../../target/idl/wrap_uranium.json')

async function writeUraniumTokenAddressToConfig(uraniumTokenAddress: string) {
    // update the token mint in the config.ts file
    const configPath = path.resolve(TOKEN_DEPLOYER_DIR, 'src/config.ts')
    let configContent = fs.readFileSync(configPath, 'utf-8')
    configContent = configContent.replace(
        /export const TOKEN_ADDRESS\s*=\s*['"][^'"]+['"]/,
        `export const TOKEN_ADDRESS = '${uraniumTokenAddress.toString()}'`,
    )
    fs.writeFileSync(configPath, configContent)
}

async function deployToken(): Promise<PublicKey> {
    console.log('\n🌟 🌟 🌟 deploying token! 🌟 🌟 🌟\n')
    // this converts the private keys to jsons in the ./.secrets folder
    spitOutWallets()

    const fundingWallet = await WalletManager.getFundingWallet()
    const common = new Common(connection, fundingWallet)
    const tokenFactory = new TokenFactory(common)

    // Deploy token with transfer fees enabled
    const tokenMint = await tokenFactory.deployToken(
        'Uranium',
        'U',
        '',
        'This is a uranium implementation with transfer fees',
        true, // enable transfer fees
        100, // initial supply
    )
    console.log('Token deployed:', tokenMint.toString())

    // update the token mint in the config.ts file
    await writeUraniumTokenAddressToConfig(tokenMint.toString())
    return tokenMint
}

async function deployOracleUpdater(): Promise<{
    oracleUpdaterIdl: any
    oracleUpdaterProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 deploying oracle updater program! 🌟 🌟 🌟\n')
    // We will not update the program ID
    console.log('Building program: 👩‍🦼 oracle-updater...')
    execSync('anchor build -p oracle-updater', { stdio: 'inherit' })

    // read the program ID from the build output
    const oracleUpdaterIdl = JSON.parse(fs.readFileSync(ORACLE_UPDATER_IDL_DIR, 'utf-8'))
    const oracleUpdaterProgramId = oracleUpdaterIdl.address
    console.log('Program ID:', oracleUpdaterProgramId)

    // Deploy the oracle updater program
    execSync(`anchor deploy --provider.cluster ${RPC_URL} -p oracle-updater`, { stdio: 'inherit' })

    return {
        oracleUpdaterIdl,
        oracleUpdaterProgramId,
    }
}
async function deployWrappedToken(): Promise<{
    wrapUraniumIdl: any
    wrapUraniumProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 deploying wrapped token program! 🌟 🌟 🌟\n')

    console.log('Building program: ☢️ wrap-uranium...')
    execSync('anchor build -p wrap-uranium', { stdio: 'inherit' })

    // read the program ID from the build output
    const wrapUraniumIdl = JSON.parse(fs.readFileSync(WRAP_URANIUM_IDL_DIR, 'utf-8'))
    const wrapUraniumProgramId = wrapUraniumIdl.address
    console.log('Program ID:', wrapUraniumProgramId)

    // Deploy the wrapped token program
    execSync(`anchor deploy --provider.cluster ${RPC_URL} -p wrap-uranium`, { stdio: 'inherit' })

    //
    return {
        wrapUraniumIdl,
        wrapUraniumProgramId,
    }
}

export async function initializeWrappedTokenWithPoR(wrapUraniumIDL: any, uraniumTokenAddress: string) {
    console.log('\n🌟 🌟 🌟 initializing wrapped token with PoR and depositing mint authority! 🌟 🌟 🌟\n')
    // Import the latest config values
    const wrapUraniumProgramId = wrapUraniumIDL.address

    console.log('Initializing wrapped token...')
    console.log('Program ID from idl:', wrapUraniumProgramId)

    console.log('💰 Reading wallet...')

    const tokenAuthority = await WalletManager.getTokenAuthority()
    const wallet = new anchor.Wallet(tokenAuthority)

    console.log('☕️ Setting provider and program...')

    const provider = new anchor.AnchorProvider(anchorConnection, wallet, {})
    anchor.setProvider(provider)

    const programWrapUranium = new anchor.Program(wrapUraniumIDL as any, provider)

    console.log('🎭 Program ID from idl:', programWrapUranium.programId.toBase58())
    console.log('🎭 Token address:', uraniumTokenAddress)

    const mint = new anchor.web3.PublicKey(uraniumTokenAddress)
    console.log('🏦 mint:', mint.toBase58())

    console.log('🪝 Preparing PDAs')
    const [wrappedMintPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('wrapped_mint'), mint.toBuffer()],
        programWrapUranium.programId,
    )

    const [configPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config'), mint.toBuffer()],
        programWrapUranium.programId,
    )

    const [feeRebateReservePDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('fee_rebate_reserve'), mint.toBuffer()],
        programWrapUranium.programId,
    )

    console.log('wrappedMintPDA:', wrappedMintPDA.toBase58())
    console.log('configPDA:', configPDA.toBase58())
    console.log('feeRebateReservePDA:', feeRebateReservePDA.toBase58())

    const uraniumATA = await getAssociatedTokenAddress(
        mint,
        configPDA,
        true, // allowOwnerOffCurve
        TOKEN_2022_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
    )
    console.log('uraniumATA:', uraniumATA.toBase58())

    console.log('Initializing!')
    console.log('wallet.publicKey:', wallet.publicKey)
    console.log('mint:', mint)
    console.log('wrappedMintPDA:', wrappedMintPDA)
    console.log('configPDA:', configPDA)

    const initializeProgramIx = await programWrapUranium.methods
        .initialize()
        .accountsPartial({
            signer: wallet.publicKey, // Wallet's public key (signer)
            config: configPDA,
            mint: mint,
            wrappedMint: wrappedMintPDA,
            mint_ata: uraniumATA,
            fee_rebate_reserve: feeRebateReservePDA,
            token_program: TOKEN_2022_PROGRAM_ID,
            associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
            system_program: SystemProgram.programId,
        })
        .instruction()
    const depositMintAuthorityIx = await programWrapUranium.methods
        .depositMintAuthority()
        .accountsPartial({
            signer: wallet.publicKey,
            config: configPDA,
            mint: mint,
            token_program: TOKEN_2022_PROGRAM_ID,
        })
        .signers([wallet.payer])
        .instruction()

    console.log('initializeProgramIx:', initializeProgramIx)
    console.log('depositMintAuthorityIx:', depositMintAuthorityIx)
    console.log('config.authority:', configPDA.toBase58())
    console.log('wallet.publicKey:', wallet.publicKey.toBase58())
    const transaction = new anchor.web3.Transaction().add(initializeProgramIx).add(depositMintAuthorityIx)

    try {
        const tx = await anchor.web3.sendAndConfirmTransaction(anchorConnection, transaction, [wallet.payer], {
            commitment: 'confirmed',
        })
        console.log('\n🎉 Transaction successful! 🎉\n Signature:', tx)
    } catch (e: any) {
        console.error('Transaction failed', e)
        console.log(e.getLogs())
    }
}

async function main(
    uraniumTokenAddress?: string,
    useExistingWrapUraniumIdl?: boolean,
    useExistingOracleUpdaterIdl?: boolean,
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

    // const tokenMint = await deployToken()

    // const { wrapUraniumIdl, wrapUraniumProgramId } = await deployWrappedToken()
    let tokenMint: PublicKey
    let wrapUraniumIdl: any
    let oracleUpdaterIdl: any

    if (!uraniumTokenAddress) {
        tokenMint = await deployToken()
        // wait 10 seconds for the deployment to settle
        await new Promise((resolve) => setTimeout(resolve, 10000))
    } else {
        tokenMint = new PublicKey(uraniumTokenAddress)
        await writeUraniumTokenAddressToConfig(uraniumTokenAddress)
    }

    if (useExistingOracleUpdaterIdl) {
        oracleUpdaterIdl = JSON.parse(await fs.promises.readFile(path.resolve(ORACLE_UPDATER_IDL_DIR), 'utf-8'))
        console.log('Using existing oracleUpdaterIdl:', oracleUpdaterIdl)
    } else {
        const { oracleUpdaterIdl: idl_from_new_deployment } = await deployOracleUpdater()
        oracleUpdaterIdl = idl_from_new_deployment
        await new Promise((resolve) => setTimeout(resolve, 10000))
    }

    if (useExistingWrapUraniumIdl) {
        wrapUraniumIdl = JSON.parse(await fs.promises.readFile(path.resolve(WRAP_URANIUM_IDL_DIR), 'utf-8'))
        console.log('Using existing wrapUraniumIdl:', wrapUraniumIdl)
    } else {
        const { wrapUraniumIdl: idl_from_new_deployment } = await deployWrappedToken()
        wrapUraniumIdl = idl_from_new_deployment
        await new Promise((resolve) => setTimeout(resolve, 10000))
    }

    await initializeWrappedTokenWithPoR(wrapUraniumIdl, tokenMint.toBase58())
}

main()
// async function main(uraniumTokenAddress?: string, useExistingWrapUraniumIdl?: boolean) {
//     try {
//         // Check if we're connected to testnet or devnet
//         const endpoint = connection.rpcEndpoint
//         console.log('endpoint', endpoint)
//         if (!endpoint.includes('testnet') && !endpoint.includes('devnet')) {
//             console.error('Error: Not connected to testnet or devnet!')
//             console.error(`Current endpoint: ${endpoint}`)

//             if (process.env.USE_TESTNET === 'devnet') {
//                 // Allow devnet
//             } else {
//                 process.exit(1)
//             }
//         }

//         // Show network information
//         const network = NETWORK_USED
//         if (network !== 'testnet' && network !== 'devnet') {
//             console.error('Error: Not connected to testnet or devnet!')
//             console.log('network:', network)
//             console.error(`Current endpoint: ${endpoint}`)
//             process.exit(1)
//         }
//         console.log('\n=== Deployment Information ===')
//         console.log(`Network: ${network}`)
//         console.log(`RPC URL: ${endpoint}`)
//         console.log('=============================\n')

//         let tokenMint: PublicKey
//         let idl: any
//         if (!uraniumTokenAddress) {
//             tokenMint = await deployToken()
//             // wait 10 seconds for the deployment to settle
//             await new Promise((resolve) => setTimeout(resolve, 10000))
//         } else {
//             tokenMint = new PublicKey(uraniumTokenAddress)
//         }

//         if (useExistingWrapUraniumIdl) {
//             idl = JSON.parse(
//                 await fs.promises.readFile(
//                     path.resolve(__dirname, '../target-multisig/idl/wrap_uranium.json'),
//                     'utf-8',
//                 ),
//             )
//             console.log('Using existing idl:', idl)
//         } else {
//             const { idl: idl_from_new_deployment } = await deployWrappedToken()
//             idl = idl_from_new_deployment
//             // wait 10 seconds for the deployment to settle
//             await new Promise((resolve) => setTimeout(resolve, 10000))
//             await extractTargetFiles()
//         }

//         // Initialize the wrapped token with the new two-step process
//         await initializeWrappedTokenWithPoR(idl, tokenMint.toBase58())
//     } catch (error) {
//         console.error('Deployment failed:', error)
//         process.exit(1)
//     }
// }

// main('CXyYRtfJGYiCkRWYj8dAbbtZH1aKq1DRok7ePNkV3aqX', false)
