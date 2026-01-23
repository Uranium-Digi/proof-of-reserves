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
    newPendingAuthority?: string
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
                case 'new-pending-authority':
                    result.newPendingAuthority = value
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
Usage: npx ts-node src/scripts/set-pending-authority.ts [options]

Sets a new pending authority for the config. The pending authority can then
call accept_authority to become the new authority (two-step transfer).

Required arguments:
  --program-id <address>            The proof-of-reserves program address
  --mint <address>                  The U token mint address
  --signer <path>                   Path to the signer keypair JSON file (must be current authority)
  --new-pending-authority <pubkey>  Public key of the new pending authority

Optional arguments:
  --network <network>               Network to use: devnet, testnet, mainnet (default: devnet)

Examples:
  # Set pending authority on devnet
  npx ts-node src/scripts/set-pending-authority.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/authority.json \\
    --new-pending-authority NewAuthorityPubkey

  # Set pending authority on mainnet
  npx ts-node src/scripts/set-pending-authority.ts \\
    --program-id 3fxTbAzpAy2i7NdywrKpY6CGPmSqxwYtWWXS7Q5NJMB9 \\
    --mint UuGEwN9aeh676ufphbavfssWVxH7BJCqacq1RYhco8e \\
    --signer ./keypairs/authority.json \\
    --network mainnet \\
    --new-pending-authority NewAuthorityPubkey
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

interface SetPendingAuthorityParams {
    programId: string
    mintAddress: string
    signerPath: string
    network: Network
    newPendingAuthority: PublicKey
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

export async function setPendingAuthority(params: SetPendingAuthorityParams): Promise<string> {
    const { programId, mintAddress, signerPath, network, newPendingAuthority } = params

    console.log('Setting pending authority...')
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

    const currentPendingAuthority = currentConfig.pendingAuthority.toBase58()
    const newPendingAuthorityStr = newPendingAuthority.toBase58()

    console.log('\n' + '='.repeat(100))
    console.log('PENDING AUTHORITY CHANGE')
    console.log('='.repeat(100))
    console.log(`  Current authority:         ${currentConfig.authority.toBase58()}`)
    console.log(`  Current pending authority: ${currentPendingAuthority}`)
    console.log(`  New pending authority:     ${newPendingAuthorityStr}`)
    console.log('-'.repeat(100))
    console.log('\nAfter this transaction, the new pending authority can call accept_authority')
    console.log('to become the new authority.\n')

    const confirmed = await promptConfirmation('Do you want to proceed? (y/n): ')
    if (!confirmed) {
        console.log('Operation cancelled.')
        process.exit(0)
    }

    console.log('\nSubmitting transaction...')

    const tx = await program.methods
        .setPendingAuthority()
        .accountsPartial({
            signer: wallet.publicKey,
            configPda: configPDA,
            u: mint,
            newPendingAuthority: newPendingAuthority,
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

    if (!parsed.newPendingAuthority) {
        console.error('Error: --new-pending-authority is required')
        process.exit(1)
    }

    await setPendingAuthority({
        programId: parsed.programId,
        mintAddress: parsed.mint,
        signerPath: parsed.signer,
        network: parsed.network,
        newPendingAuthority: new PublicKey(parsed.newPendingAuthority),
    })
}

main().catch((err) => {
    console.error('Error:', err)
    process.exit(1)
})
