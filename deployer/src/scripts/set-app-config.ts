import * as anchor from '@coral-xyz/anchor'
import { Keypair, PublicKey } from '@solana/web3.js'
import * as readline from 'readline'
import * as fs from 'fs'
import 'dotenv/config'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const proofOfReservesIdl = require('../../../target/idl/proof_of_reserves.json')

type Network = 'devnet' | 'testnet' | 'mainnet'

interface ParsedArgs {
    programId?: string
    mint?: string
    signer?: string
    network: Network
    issuanceFeeRate?: number
    redemptionFeeRate?: number
    feedId?: Buffer
    issueAuthority?: PublicKey
    redeemAuthority?: PublicKey
    updateAuthority?: PublicKey
}

function parseArgs(args: string[]): ParsedArgs {
    const result: ParsedArgs = { network: 'devnet' }

    for (let i = 0; i < args.length; i++) {
        const arg = args[i]

        if (arg.startsWith('--')) {
            const [key, inlineValue] = arg.slice(2).split('=')
            const value = inlineValue ?? args[++i]

            if (!value || value.startsWith('--')) {
                throw new Error(`Missing value for argument: --${key}`)
            }

            switch (key) {
                case 'program-id':
                    result.programId = value
                    break
                case 'mint':
                    result.mint = value
                    break
                case 'signer':
                    result.signer = value
                    break
                case 'network':
                    if (value !== 'devnet' && value !== 'testnet' && value !== 'mainnet') {
                        throw new Error(`Invalid network: ${value}. Must be devnet, testnet, or mainnet`)
                    }
                    result.network = value
                    break
                case 'issuance-fee-rate':
                    result.issuanceFeeRate = parseInt(value, 10)
                    if (isNaN(result.issuanceFeeRate)) {
                        throw new Error(`Invalid issuance fee rate: ${value}`)
                    }
                    break
                case 'redemption-fee-rate':
                    result.redemptionFeeRate = parseInt(value, 10)
                    if (isNaN(result.redemptionFeeRate)) {
                        throw new Error(`Invalid redemption fee rate: ${value}`)
                    }
                    break
                case 'feed-id':
                    if (value.length !== 64) {
                        throw new Error('Feed ID must be exactly 64 hex characters (32 bytes)')
                    }
                    result.feedId = Buffer.from(value, 'hex')
                    break
                case 'issue-authority':
                    result.issueAuthority = new PublicKey(value)
                    break
                case 'redeem-authority':
                    result.redeemAuthority = new PublicKey(value)
                    break
                case 'update-authority':
                    result.updateAuthority = new PublicKey(value)
                    break
                default:
                    throw new Error(`Unknown argument: --${key}`)
            }
        } else {
            throw new Error(`Unexpected argument: ${arg}. Use --key=value or --key value format.`)
        }
    }

    return result
}

function printUsage(): void {
    console.log(`
Usage: npx ts-node src/scripts/set-app-config.ts [options]

Required arguments:
  --program-id <address>        The proof-of-reserves program address
  --mint <address>              The U token mint address
  --signer <path>               Path to the signer keypair JSON file (must be config authority)

Optional arguments:
  --network <network>           Network to use: devnet, testnet, mainnet (default: devnet)
  --issuance-fee-rate <number>  New issuance fee rate (0-10000, where 10000 = 100%)
  --redemption-fee-rate <num>   New redemption fee rate (0-10000, where 10000 = 100%)
  --feed-id <hex>               The 32-byte feed ID as a hex string (64 characters)
  --issue-authority <pubkey>    Public key for new issue authority
  --redeem-authority <pubkey>   Public key for new redeem authority
  --update-authority <pubkey>   Public key for new update authority

Examples:
  # Update fee rates on devnet (1% issuance, 0.5% redemption)
  npx ts-node src/scripts/set-app-config.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/authority.json \\
    --issuance-fee-rate 100 \\
    --redemption-fee-rate 50

  # Update on mainnet
  npx ts-node src/scripts/set-app-config.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/authority.json \\
    --network mainnet \\
    --issuance-fee-rate 100
`)
}

async function promptConfirmation(message: string): Promise<boolean> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    })

    return new Promise((resolve) => {
        rl.question(message, (answer) => {
            rl.close()
            resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes')
        })
    })
}

interface CurrentConfig {
    authority: PublicKey
    issueAuthority: PublicKey
    redeemAuthority: PublicKey
    updateAuthority: PublicKey
    issuanceFeeRate: number
    redemptionFeeRate: number
    feedId: number[]
    pendingAuthority: PublicKey
}

interface SetAppConfigParams {
    programId: string
    mintAddress: string
    signerPath: string
    network: Network
    newIssuanceFeeRate?: number
    newRedemptionFeeRate?: number
    feedId?: Buffer
    newIssueAuthority?: PublicKey
    newRedeemAuthority?: PublicKey
    newUpdateAuthority?: PublicKey
}

function loadKeypair(path: string): Keypair {
    const secretKey = JSON.parse(fs.readFileSync(path, 'utf-8'))
    return Keypair.fromSecretKey(new Uint8Array(secretKey))
}

function getRpcUrl(network: Network): string {
    switch (network) {
        case 'devnet':
            return process.env.DEVNET_RPC_URL || 'https://api.devnet.solana.com'
        case 'testnet':
            return process.env.TESTNET_RPC_URL || 'https://api.testnet.solana.com'
        case 'mainnet':
            return process.env.MAINNET_RPC_URL || 'https://api.mainnet-beta.solana.com'
    }
}

async function fetchCurrentConfig(program: anchor.Program, configPDA: PublicKey): Promise<CurrentConfig> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config = await (program.account as any).config.fetch(configPDA)
    return config as CurrentConfig
}

export async function setAppConfig(params: SetAppConfigParams): Promise<string> {
    const { programId, mintAddress, signerPath, network } = params

    console.log('Setting app config...')
    console.log('Network:', network)

    const signer = loadKeypair(signerPath)
    const wallet = new anchor.Wallet(signer)

    console.log('Signer:', wallet.publicKey.toBase58())

    const rpcUrl = getRpcUrl(network)
    const connection = new anchor.web3.Connection(rpcUrl, 'confirmed')
    const provider = new anchor.AnchorProvider(connection, wallet, { commitment: 'confirmed' })

    const programPubkey = new PublicKey(programId)
    const mint = new PublicKey(mintAddress)

    const idlWithCustomAddress = { ...proofOfReservesIdl, address: programId }
    const program = new anchor.Program(idlWithCustomAddress, provider)

    console.log('Program ID:', programPubkey.toBase58())
    console.log('Mint address:', mint.toBase58())

    const [configPDA] = PublicKey.findProgramAddressSync(
        [Buffer.from('config_pda'), mint.toBuffer()],
        programPubkey,
    )

    console.log('Config PDA:', configPDA.toBase58())

    const currentConfig = await fetchCurrentConfig(program, configPDA)

    const newIssuanceFeeRate = params.newIssuanceFeeRate ?? currentConfig.issuanceFeeRate
    const newRedemptionFeeRate = params.newRedemptionFeeRate ?? currentConfig.redemptionFeeRate
    const feedId = params.feedId ?? Buffer.from(currentConfig.feedId)
    const newIssueAuthority = params.newIssueAuthority ?? currentConfig.issueAuthority
    const newRedeemAuthority = params.newRedeemAuthority ?? currentConfig.redeemAuthority
    const newUpdateAuthority = params.newUpdateAuthority ?? currentConfig.updateAuthority

    if (newIssuanceFeeRate > 10_000 || newRedemptionFeeRate > 10_000) {
        throw new Error('Fee rates must be <= 10000 (100%)')
    }

    if (feedId.length !== 32) {
        throw new Error('Feed ID must be exactly 32 bytes')
    }

    const currentFeedIdHex = Buffer.from(currentConfig.feedId).toString('hex')
    const newFeedIdHex = feedId.toString('hex')

    const formatChange = (label: string, current: string, next: string): string => {
        const changed = current !== next
        const marker = changed ? '*' : ' '
        return `${marker} ${label.padEnd(22)} ${current.padEnd(50)} -> ${next}`
    }

    console.log('\n' + '='.repeat(140))
    console.log('CONFIG CHANGES SUMMARY')
    console.log('='.repeat(140))
    console.log(`  ${'Field'.padEnd(22)} ${'Current Value'.padEnd(50)}    New Value`)
    console.log('-'.repeat(140))
    console.log(formatChange('Issuance fee rate', String(currentConfig.issuanceFeeRate), String(newIssuanceFeeRate)))
    console.log(formatChange('Redemption fee rate', String(currentConfig.redemptionFeeRate), String(newRedemptionFeeRate)))
    console.log(formatChange('Feed ID', currentFeedIdHex, newFeedIdHex))
    console.log(formatChange('Issue authority', currentConfig.issueAuthority.toBase58(), newIssueAuthority.toBase58()))
    console.log(formatChange('Redeem authority', currentConfig.redeemAuthority.toBase58(), newRedeemAuthority.toBase58()))
    console.log(formatChange('Update authority', currentConfig.updateAuthority.toBase58(), newUpdateAuthority.toBase58()))
    console.log('-'.repeat(140))
    console.log('(* indicates changed values)\n')

    const confirmed = await promptConfirmation('Do you want to proceed with this update? (y/n): ')
    if (!confirmed) {
        console.log('Update cancelled.')
        process.exit(0)
    }

    console.log('\nSubmitting transaction...')

    const tx = await program.methods
        .setAppConfig(newIssuanceFeeRate, newRedemptionFeeRate, feedId)
        .accountsPartial({
            signer: wallet.publicKey,
            configPda: configPDA,
            u: mint,
            newIssueAuthority: newIssueAuthority,
            newRedeemAuthority: newRedeemAuthority,
            newUpdateAuthority: newUpdateAuthority,
        })
        .signers([wallet.payer])
        .rpc({ commitment: 'confirmed' })

    console.log('\nTransaction successful! Signature:', tx)
    return tx
}

async function main() {
    const args = process.argv.slice(2)

    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        printUsage()
        process.exit(args.length === 0 ? 1 : 0)
    }

    const parsed = parseArgs(args)

    if (!parsed.programId) {
        console.error('Error: --program-id is required')
        process.exit(1)
    }

    if (!parsed.mint) {
        console.error('Error: --mint is required')
        process.exit(1)
    }

    if (!parsed.signer) {
        console.error('Error: --signer is required')
        process.exit(1)
    }

    await setAppConfig({
        programId: parsed.programId,
        mintAddress: parsed.mint,
        signerPath: parsed.signer,
        network: parsed.network,
        newIssuanceFeeRate: parsed.issuanceFeeRate,
        newRedemptionFeeRate: parsed.redemptionFeeRate,
        feedId: parsed.feedId,
        newIssueAuthority: parsed.issueAuthority,
        newRedeemAuthority: parsed.redeemAuthority,
        newUpdateAuthority: parsed.updateAuthority,
    })
}

main().catch((err) => {
    console.error('Error:', err)
    process.exit(1)
})
