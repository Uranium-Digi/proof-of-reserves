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
Usage: npx ts-node src/scripts/accept-authority.ts [options]

Accepts the authority role. The signer must be the current pending authority.
This completes the two-step authority transfer process.

Required arguments:
  --program-id <address>  The proof-of-reserves program address
  --mint <address>        The U token mint address
  --signer <path>         Path to the signer keypair JSON file (must be pending authority)

Optional arguments:
  --network <network>     Network to use: devnet, testnet, mainnet (default: devnet)

Examples:
  # Accept authority on devnet
  npx ts-node src/scripts/accept-authority.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/new-authority.json

  # Accept authority on mainnet
  npx ts-node src/scripts/accept-authority.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/new-authority.json \\
    --network mainnet
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

interface AcceptAuthorityParams {
    programId: string
    mintAddress: string
    signerPath: string
    network: Network
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

export async function acceptAuthority(params: AcceptAuthorityParams): Promise<string> {
    const { programId, mintAddress, signerPath, network } = params

    console.log('Accepting authority...')
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

    const currentAuthority = currentConfig.authority.toBase58()
    const pendingAuthority = currentConfig.pendingAuthority.toBase58()
    const signerPubkey = wallet.publicKey.toBase58()

    // Check if pending authority is set
    if (currentConfig.pendingAuthority.equals(PublicKey.default)) {
        console.error('\nError: No pending authority set. Cannot accept authority.')
        process.exit(1)
    }

    // Check if signer is the pending authority
    if (pendingAuthority !== signerPubkey) {
        console.error(`\nError: Signer (${signerPubkey}) is not the pending authority (${pendingAuthority})`)
        process.exit(1)
    }

    console.log('\n' + '='.repeat(100))
    console.log('ACCEPT AUTHORITY')
    console.log('='.repeat(100))
    console.log(`  Current authority:  ${currentAuthority}`)
    console.log(`  Pending authority:  ${pendingAuthority}`)
    console.log(`  Signer:             ${signerPubkey}`)
    console.log('-'.repeat(100))
    console.log(`\nAfter this transaction:`)
    console.log(`  - Authority will be: ${signerPubkey}`)
    console.log(`  - Pending authority will be cleared`)
    console.log('')

    const confirmed = await promptConfirmation('Do you want to proceed? (y/n): ')
    if (!confirmed) {
        console.log('Operation cancelled.')
        process.exit(0)
    }

    console.log('\nSubmitting transaction...')

    const tx = await program.methods
        .acceptAuthority()
        .accountsPartial({
            signer: wallet.publicKey,
            configPda: configPDA,
            u: mint,
        })
        .signers([wallet.payer])
        .rpc({ commitment: 'confirmed' })

    console.log('\nTransaction successful! Signature:', tx)
    console.log(`\nYou are now the authority for this config.`)
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

    await acceptAuthority({
        programId: parsed.programId,
        mintAddress: parsed.mint,
        signerPath: parsed.signer,
        network: parsed.network,
    })
}

main().catch((err) => {
    console.error('Error:', err)
    process.exit(1)
})
