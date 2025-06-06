import { exec, execSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import * as dotenv from 'dotenv'
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js'
import { spitOutWallets } from '../src/convertKey'
import WalletManager from '../src/WalletManager'
import Common from '../src/Common'
import { TokenFactory } from '../src/TokenFactory'
import { connection, RPC_URL, NETWORK_USED, wrapUraniumProgram, uraniumToken } from '../src/config'
import * as anchor from '@coral-xyz/anchor'
import {
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    getAssociatedTokenAddress,
    getOrCreateAssociatedTokenAccount,
    mintTo,
} from '@solana/spl-token'
import { anchorConnection } from '../src/config'
import { changeMetadata, createAndMintTokensViaMetaplex } from '../src/metaplex/metaplexDeployToken'

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

async function anchorKeysSync() {
    execSync('anchor keys sync', { stdio: 'inherit' })
}
// async function deployToken(): Promise<PublicKey> {
//     console.log('\n🌟 🌟 🌟 deploying token! 🌟 🌟 🌟\n')
//     // this converts the private keys to jsons in the ./.secrets folder
//     spitOutWallets()

//     const fundingWallet = await WalletManager.getFundingWallet()
//     const common = new Common(connection, umi, fundingWallet)
//     const tokenFactory = new TokenFactory(common)

//     // Deploy token with transfer fees enabled
//     const tokenMint = await tokenFactory.deployToken(
//         'Lemon Cake',
//         'LEMON',
//         'https://raw.githubusercontent.com/Uranium-Digi/lemon-cake/refs/heads/main/0978fe9e1d7932debba36c233b4e34c7.jpg',
//         'This token is a lemon cake.',
//         10000, // initial supply
//     )
//     console.log('Token deployed:', tokenMint.toString())
//     await new Promise((resolve) => setTimeout(resolve, 10000))
//     // update the token mint in the config.ts file
//     await writeUraniumTokenAddressToConfig(tokenMint.toString())

//     return tokenMint
// }

async function deployOracleUpdater(): Promise<{
    oracleUpdaterIdl: any
    oracleUpdaterProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 deploying oracle updater program! 🌟 🌟 🌟\n')

    execSync('anchor keys list', { stdio: 'inherit' })
    // We will not update the program ID
    console.log('Building program: 👩👩‍🦼 oracle-updater...')
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
    await new Promise((resolve) => setTimeout(resolve, 10000))
    //
    return {
        wrapUraniumIdl,
        wrapUraniumProgramId,
    }
}

export async function initialize(
    tokenAuthority: Keypair,
    fundingWallet: Keypair,
    wrapUraniumIDL: any,
    uraniumTokenAddress: string,
): Promise<{
    u: string
    wu: string
    configPda: string
    configPdaUAta: string
    feeRebateReserveUAta: string
    wrapUraniumProgramId: string
}> {
    console.log('\n🌟 🌟 🌟 initializing wrapped token with PoR! 🌟 🌟 🌟\n')

    const programWrapUranium = await wrapUraniumProgram(wrapUraniumIDL)
    const u = await uraniumToken(uraniumTokenAddress)

    console.log('🎭 programWrapUranium program ID from idl:', programWrapUranium.programId.toBase58())

    console.log('🪝 Preparing PDAs')
    const [wu] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('wu'), u.toBuffer()],
        programWrapUranium.programId,
    )

    const [configPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), u.toBuffer()],
        programWrapUranium.programId,
    )

    const configPdaUAta = await getAssociatedTokenAddress(
        u,
        configPda,
        true, // allowOwnerOffCurve
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
    )

    const [feeRebateReserveUAta] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('fee_rebate_reserve_u_ata'), u.toBuffer()],
        programWrapUranium.programId,
    )

    console.log('🏦 u :', u.toBase58())
    console.log('🎁 wu:', wu.toBase58())
    console.log('🏗️ configPda:', configPda.toBase58())
    console.log('🏦🏗️ configPdaUAta:', configPdaUAta.toBase58())
    console.log('🏦🤑 feeRebateReserveUAta:', feeRebateReserveUAta.toBase58())

    const initializeProgramIx = await programWrapUranium.methods
        .initialize()
        .accountsPartial({
            signer: tokenAuthority.publicKey,
            u, //
            wu, //
            configPda, //
            configPdaUAta,
            feeRebateReserveUAta,
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
            wu: wu.toBase58(),
            configPda: configPda.toBase58(),
            configPdaUAta: configPdaUAta.toBase58(),
            feeRebateReserveUAta: feeRebateReserveUAta.toBase58(),
            wrapUraniumProgramId: programWrapUranium.programId.toBase58(),
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
    wrapUraniumIDL: any,
    uraniumTokenAddress: string,
) {
    console.log('\n🌟 🌟 🌟 depositing mint authority! 🌟 🌟 🌟\n')
    const u = await uraniumToken(uraniumTokenAddress)
    const programWrapUranium = await wrapUraniumProgram(wrapUraniumIDL)

    const [configPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), u.toBuffer()],
        programWrapUranium.programId,
    )

    const depositMintAuthorityIx = await programWrapUranium.methods
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

export async function depositWithdrawWithheldAuthority(
    tokenAuthority: Keypair,
    fundingWallet: Keypair,
    wrapUraniumIDL: any,
    uraniumTokenAddress: string,
) {
    console.log('\n🌟 🌟 🌟 depositing withdrawWithheld authority! 🌟 🌟 🌟\n')
    const u = await uraniumToken(uraniumTokenAddress)
    const programWrapUranium = await wrapUraniumProgram(wrapUraniumIDL)

    const [configPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), u.toBuffer()],
        programWrapUranium.programId,
    )

    const depositMintAuthorityIx = await programWrapUranium.methods
        .depositWithdrawWithheldAuthority()
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
        console.log('\n🎉 DepositWithdrawWithheldAuthority Transaction successful! 🎉\n Signature:', tx)
        await new Promise((resolve) => setTimeout(resolve, 10000))
    } catch (e: any) {
        console.error('DepositMintAuthority failed', e)
        console.log(e.getLogs())
    }
}

// async function main(
//     uraniumTokenAddress?: string,
//     useExistingWrapUraniumIdl?: boolean,
//     useExistingOracleUpdaterIdl?: boolean,
// ) {
//     // Check if we're connected to testnet or devnet
//     const endpoint = connection.rpcEndpoint
//     console.log('endpoint', endpoint)
//     if (!endpoint.includes('testnet') && !endpoint.includes('devnet')) {
//         console.error('Error: Not connected to testnet or devnet!')
//         console.error(`Current endpoint: ${endpoint}`)

//         if (process.env.USE_TESTNET === 'devnet') {
//             // Allow devnet
//         } else {
//             process.exit(1)
//         }
//     }

//     // Show network information
//     const network = NETWORK_USED
//     if (network !== 'testnet' && network !== 'devnet') {
//         console.error('Error: Not connected to testnet or devnet!')
//         console.log('network:', network)
//         console.error(`Current endpoint: ${endpoint}`)
//         process.exit(1)
//     }
//     console.log('\n=== Deployment Information ===')
//     console.log(`Network: ${network}`)
//     console.log(`RPC URL: ${endpoint}`)
//     console.log('=============================\n')

//     let u: PublicKey
//     let wrapUraniumIdl: any
//     let oracleUpdaterIdl: any

//     if (!uraniumTokenAddress) {
//         u = await deployToken()
//     } else {
//         u = new PublicKey(uraniumTokenAddress)
//         await writeUraniumTokenAddressToConfig(uraniumTokenAddress)
//     }

//     if (useExistingOracleUpdaterIdl) {
//         oracleUpdaterIdl = JSON.parse(await fs.promises.readFile(path.resolve(ORACLE_UPDATER_IDL_DIR), 'utf-8'))
//         console.log('Using existing oracleUpdaterIdl:', oracleUpdaterIdl)
//     } else {
//         const { oracleUpdaterIdl: idl_from_new_deployment } = await deployOracleUpdater()
//         oracleUpdaterIdl = idl_from_new_deployment
//         await new Promise((resolve) => setTimeout(resolve, 10000))
//     }

//     if (useExistingWrapUraniumIdl) {
//         wrapUraniumIdl = JSON.parse(await fs.promises.readFile(path.resolve(WRAP_URANIUM_IDL_DIR), 'utf-8'))
//         console.log('Using existing wrapUraniumIdl:', wrapUraniumIdl)
//     } else {
//         const { wrapUraniumIdl: idl_from_new_deployment } = await deployWrappedToken()
//         wrapUraniumIdl = idl_from_new_deployment
//     }

//     const tokenAuthority = await WalletManager.getTokenAuthority()
//     const fundingWallet = await WalletManager.getFundingWallet()

//     const {
//         u: uAddress,
//         wu: wuAddress,
//         configPda: configPdaAddress,
//         configPdaUAta: configPdaUAtaAddress,
//         feeRebateReserveUAta: feeRebateReserveUAtaAddress,
//         wrapUraniumProgramId: wrapUraniumProgramId,
//     } = await initialize(tokenAuthority, fundingWallet, wrapUraniumIdl, u.toBase58())

//     await depositMintAuthority(tokenAuthority, fundingWallet, wrapUraniumIdl, u.toBase58())

//     // Save addresses to file
//     await saveAddressesToFile({
//         u: uAddress,
//         wu: wuAddress,
//         configPda: configPdaAddress,
//         configPdaUAta: configPdaUAtaAddress,
//         feeRebateReserveUAta: feeRebateReserveUAtaAddress,
//         wrapUraniumProgramId: wrapUraniumProgramId,
//         oracleUpdaterProgramId: oracleUpdaterIdl.address,
//     })
// }

async function saveAddressesToFile(addresses: {
    u: string
    wu: string
    configPda: string
    configPdaUAta: string
    feeRebateReserveUAta: string
    wrapUraniumProgramId: string
    oracleUpdaterProgramId: string
}) {
    const addressesPath = path.resolve(TOKEN_DEPLOYER_DIR, 'deployed-addresses.json')
    const timestamp = new Date().toISOString()
    const data = {
        timestamp,
        network: NETWORK_USED,
        addresses,
    }
    fs.writeFileSync(addressesPath, JSON.stringify(data, null, 2))
    console.log('\n📝 Addresses saved to:', addressesPath)
}

async function main() {
    // await deployToken()
    const uraniumTokenAddress = await createAndMintTokensViaMetaplex(
        'Lemon Cake',
        'LEMON',
        'This is a lemon cake.',
        'https://raw.githubusercontent.com/solana-developers/opos-asset/main/assets/CompressedCoil/image.png',
        BigInt(12352 * 10 ** 9),
    )
    await writeUraniumTokenAddressToConfig(uraniumTokenAddress.toString())
}
main()
