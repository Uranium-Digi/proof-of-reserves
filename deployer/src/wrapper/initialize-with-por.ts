import { readFile } from 'fs/promises'
import * as anchor from '@coral-xyz/anchor'
import { TOKEN_2022_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, getAssociatedTokenAddress } from '@solana/spl-token'
import 'dotenv/config'
import { SystemProgram } from '@solana/web3.js'
import { anchorConnection } from '../config'

export async function initializeWrappedTokenWithPoR(idl: any, tokenAddress: string) {
    // Import the latest config values
    const programId = idl.address

    console.log('Initializing wrapped token...')
    console.log('Program ID from idl:', idl.address)

    console.log('programId:', programId)

    // Validate required environment variables
    // const requiredEnvVars = ['TESTNET_PUBLIC_RPC_URL', 'TOKEN_AUTHORITY_PATH']
    // const missingVars = requiredEnvVars.filter((varName) => !process.env[varName])
    // if (missingVars.length > 0) {
    //     console.error('Missing required environment variables:', missingVars.join(', '))
    //     return
    // }

    console.log('💰 Reading wallet...')
    const keyFile = await readFile(process.env.TOKEN_AUTHORITY_PATH!)
    const keypair: anchor.web3.Keypair = anchor.web3.Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(keyFile.toString())),
    )
    const wallet = new anchor.Wallet(keypair)

    console.log('☕️ Setting provider and program...')

    const provider = new anchor.AnchorProvider(anchorConnection, wallet, {})
    anchor.setProvider(provider)

    const programWrapUranium = new anchor.Program(idl as any, provider)

    console.log('🎭 Program ID from idl:', programWrapUranium.programId.toBase58())
    console.log('🎭 Token address:', tokenAddress)

    // if (programWrapUranium.programId.toBase58() !== WRAP_TOKEN_PROGRAM_ID) {
    //     throw new Error('Program ID mismatch')
    // }

    const mint = new anchor.web3.PublicKey(tokenAddress)
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
    // const transaction = new anchor.web3.Transaction().add(depositMintAuthorityIx)
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
