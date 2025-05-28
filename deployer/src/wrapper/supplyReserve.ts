// import { readFile } from 'fs/promises'
// import * as anchor from '@coral-xyz/anchor'
// import { WrapUranium } from '../../target/types/wrap_uranium'
// import idl from '../../target/idl/wrap_uranium.json'

// import {
//     TOKEN_2022_PROGRAM_ID,
//     ASSOCIATED_TOKEN_PROGRAM_ID,
//     getAssociatedTokenAddress,
//     createInitializeMintInstruction,
//     getOrCreateAssociatedTokenAccount,
//     getAccount,
//     transferCheckedWithFee,
// } from '@solana/spl-token'
// import 'dotenv/config'
// import { SystemProgram } from '@solana/web3.js'
// import TokenInfo from '../TokenInfo'
// import { SPL_TOKEN_ADDRESS } from '../config'
// import WalletManager from '../WalletManager'

// const kpFile = './secret/abcwYfXEL2yCCJFUvYGkqTewLxocWK2oAw2Nqny5rnF.json'

// const mint = new anchor.web3.PublicKey('F47h2eyJNvsG7ZSpScirRF1PVjmF8H5goj1JQDTiSJrj')

// const main = async () => {
//     if (!process.env.RPC_URL) {
//         console.log('Missing required env variables')
//         return
//     }
//     console.log('RPC_URL:', process.env.RPC_URL)
//     console.log('💰 Reading wallet...')
//     const keyFile = await readFile(kpFile)
//     const keypair: anchor.web3.Keypair = anchor.web3.Keypair.fromSecretKey(
//         new Uint8Array(JSON.parse(keyFile.toString())),
//     )
//     const wallet = new anchor.Wallet(keypair)

//     console.log('☕️ Setting provider and program...')
//     const connection = new anchor.web3.Connection(process.env.RPC_URL)
//     const provider = new anchor.AnchorProvider(connection, wallet, {})
//     anchor.setProvider(provider)

//     const programWrapUranium = new anchor.Program<WrapUranium>(idl as WrapUranium, provider)
//     console.log('Program ID:', programWrapUranium.programId.toBase58())

//     console.log('🪝 Preparing PDAs')

//     const [wrappedMintPDA] = anchor.web3.PublicKey.findProgramAddressSync(
//         [Buffer.from('wrapped_mint'), mint.toBuffer()],
//         programWrapUranium.programId,
//     )

//     const [configPDA] = anchor.web3.PublicKey.findProgramAddressSync(
//         [Buffer.from('config2'), mint.toBuffer()],
//         programWrapUranium.programId,
//     )

//     const [feeRebateReservePDA] = anchor.web3.PublicKey.findProgramAddressSync(
//         [Buffer.from('fee_rebate_reserve'), mint.toBuffer()],
//         programWrapUranium.programId,
//     )

//     console.log('wrappedMintPDA:', wrappedMintPDA)
//     console.log('configPDA:', configPDA)
//     console.log('feeRebateReservePDA:', feeRebateReservePDA)

//     // This is the account of uranium tokens that the config controls.
//     const uraniumATA = await getAssociatedTokenAddress(
//         mint,
//         configPDA,
//         true, // allowOwnerOffCurve
//         TOKEN_2022_PROGRAM_ID,
//         ASSOCIATED_TOKEN_PROGRAM_ID,
//     )
//     console.log('SHIT uraniumATA:', uraniumATA.toBase58())

//     // transfer reserves from companyWallet into the fee_rebate_reserve
//     const topUpAmount = BigInt(100_000_000_000_000)
//     const tokenInfo = new TokenInfo(connection, SPL_TOKEN_ADDRESS)

//     const companyWallet = await WalletManager.getCompanyWallet()
//     const fee = await tokenInfo.getTransferFee(topUpAmount)
//     console.log('fee', fee)
//     const fromTokenAccount = await getOrCreateAssociatedTokenAccount(
//         connection,
//         wallet.payer,
//         SPL_TOKEN_ADDRESS,
//         wallet.publicKey,
//         false,
//         'confirmed',
//         undefined,
//         TOKEN_2022_PROGRAM_ID,
//         ASSOCIATED_TOKEN_PROGRAM_ID,
//     )
//     const topUpRebateReserveTx = await transferCheckedWithFee(
//         connection,
//         wallet.payer,
//         fromTokenAccount.address,
//         SPL_TOKEN_ADDRESS,
//         feeRebateReservePDA,
//         wallet.payer,
//         topUpAmount,
//         9,
//         fee,
//         [],
//         undefined,
//         TOKEN_2022_PROGRAM_ID,
//     )
//     console.log('topUpRebateReserveTx', topUpRebateReserveTx)
//     // tokenInfo.internalTransfer(companyWallet, feeRebateReservePDA, BigInt(100000000000000000000))

//     // let us see what's the reserve amount right now
//     const feeRebateReserveAccountInfo = await getAccount(
//         connection,
//         feeRebateReservePDA,
//         'confirmed',
//         TOKEN_2022_PROGRAM_ID,
//     )

//     console.log('feeRebateReservePDA:', feeRebateReservePDA)
//     console.log('feeRebateReserveAccount amount: ', feeRebateReserveAccountInfo.amount)
//     // // unwrap
//     const unwrappingDestination = wallet
//     const unwrappingDestATA = await getOrCreateAssociatedTokenAccount(
//         connection,
//         wallet.payer, // payer
//         mint,
//         unwrappingDestination.publicKey, // owner
//         false, // allowOwnerOffCurve
//         'confirmed',
//         undefined,
//         TOKEN_2022_PROGRAM_ID,
//         ASSOCIATED_TOKEN_PROGRAM_ID,
//     )
//     const signerWrappedAta = await getOrCreateAssociatedTokenAccount(
//         connection,
//         wallet.payer, // payer
//         wrappedMintPDA,
//         wallet.publicKey, // owner
//         false, // allowOwnerOffCurve
//         'confirmed',
//         undefined,
//         TOKEN_2022_PROGRAM_ID,
//         ASSOCIATED_TOKEN_PROGRAM_ID,
//     )
//     const unwrappingIx = await programWrapUranium.methods
//         .unwrap(new anchor.BN(1_000_000_000))
//         .accountsPartial({
//             signer: wallet.publicKey,
//             signerWrappedAta: signerWrappedAta.address,
//             mint: mint,
//             wrappedMint: wrappedMintPDA,
//             config: configPDA,
//             mintAta: uraniumATA,
//             destination: unwrappingDestination.publicKey,
//             destinationAta: unwrappingDestATA.address,
//             feeRebateReserve: feeRebateReservePDA,
//         })
//         .instruction()

//     const transaction = new anchor.web3.Transaction().add(unwrappingIx)

//     const tx = await anchor.web3.sendAndConfirmTransaction(connection, transaction, [wallet.payer], {
//         commitment: 'confirmed',
//     })
//     console.log('Transaction Signature:', tx)
// }

// main()
//     .then(() => {
//         console.log('done!')
//         process.exit(0)
//     })
//     .catch((e) => {
//         console.log('Error: ', e)
//         process.exit(1)
//     })
