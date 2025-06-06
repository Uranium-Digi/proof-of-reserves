import {
    Keypair,
    PublicKey,
    SystemProgram,
    Transaction,
    LAMPORTS_PER_SOL,
    sendAndConfirmTransaction,
} from '@solana/web3.js'

import { createUmi } from '@metaplex-foundation/umi-bundle-defaults'
import { mplTokenMetadata } from '@metaplex-foundation/mpl-token-metadata'

import {
    TOKEN_PROGRAM_ID,
    MINT_SIZE,
    getMinimumBalanceForRentExemptMint,
    createInitializeMintInstruction,
    createMint,
    getOrCreateAssociatedTokenAccount,
    mintTo,
} from '@solana/spl-token'
import { ASSOCIATED_PROGRAM_ID } from '@coral-xyz/anchor/dist/cjs/utils/token'
import Common from './Common'
import WalletManager from './WalletManager'
export interface TokenConfig {
    name: string
    symbol: string
    imageUri: string
    description: string
    decimals: number
    initialSupply: bigint
    vanityAddress?: Keypair | undefined
}

export class TokenDeployer {
    common: Common

    constructor(common: Common) {
        this.common = common
    }

    /**
     * Request a SOL airdrop for the payer wallet
     * @param amount Amount of SOL to request (default: 2)
     * @returns Promise<string> Transaction signature
     */
    private async requestSolAirdrop(amount: number = 2): Promise<string> {
        const network = await this.common.checkCluster(this.common.connection)
        if (network === 'mainnet') {
            throw new Error('Cannot request airdrops on mainnet')
        }

        const payer = await WalletManager.getFundingWallet()
        const currentBalance = await this.common.connection.getBalance(payer.publicKey)

        if (currentBalance >= LAMPORTS_PER_SOL * amount) {
            console.log(`Sufficient SOL balance: ${currentBalance / LAMPORTS_PER_SOL} SOL`)
            return ''
        }

        console.log(`Requesting ${amount} SOL airdrop...`)
        const signature = await this.common.connection.requestAirdrop(payer.publicKey, amount * LAMPORTS_PER_SOL)

        await this.common.connection.confirmTransaction(signature, 'confirmed')
        console.log(`Airdrop successful! Signature: ${signature}`)

        return signature
    }

    async deployToken(config: TokenConfig) {
        // Request SOL airdrop before deployment if needed
        try {
            await this.requestSolAirdrop()
        } catch (error) {
            console.warn('Failed to request SOL airdrop:', error)
            console.warn('Continuing with deployment...')
        }

        const mintKeypair = config.vanityAddress || Keypair.generate()
        const mint = mintKeypair.publicKey

        const payer = await WalletManager.getFundingWallet()
        const tokenAuthority = await WalletManager.getTokenAuthority()

        const mintAddress = await createMint(
            this.common.connection, // connection: Connection,
            payer, // payer: Signer,
            tokenAuthority.publicKey, // mintAuthority: PublicKey,
            tokenAuthority.publicKey, // freezeAuthority: PublicKey | null,
            9, // decimals: number,
            mintKeypair, // keypair = Keypair.generate(),
        )

        // --- Token metadata JSON file ---
        // https://developers.metaplex.com/guides/javascript/how-to-create-a-solana-token
        const METADATA_PROGRAM_ID = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')

        const metadata: Data = {
            name: config.name,
            symbol: config.symbol,
            uri: config.imageUri,
            sellerFeeBasisPoints: 0,
            creators: [],
        }
        const metadataPda = PublicKey.findProgramAddressSync(
            [Buffer.from('metadata'), METADATA_PROGRAM_ID.toBuffer(), mintKeypair.publicKey.toBuffer()],
            METADATA_PROGRAM_ID,
        )[0]

        console.log('metadataPda:', metadataPda)

        const tx = new Transaction().add(
            createCreateMetadataAccountInstruction(
                {
                    metadata: metadataPda,
                    mint: mintKeypair.publicKey,
                    mintAuthority: tokenAuthority.publicKey,
                    payer: payer.publicKey,
                    updateAuthority: tokenAuthority.publicKey,
                },
                {
                    createMetadataAccountArgs: {
                        data: metadata,
                        isMutable: true,
                    },
                },
            ),
        )

        await sendAndConfirmTransaction(this.common.connection, tx, [payer, tokenAuthority, mintKeypair], {
            commitment: 'confirmed',
        })

        if (config.initialSupply > BigInt(0)) {
            const tokenAccount = await getOrCreateAssociatedTokenAccount(
                this.common.connection,
                payer,
                mint,
                tokenAuthority.publicKey,
                false,
                'confirmed',
                undefined,
                TOKEN_PROGRAM_ID,
                ASSOCIATED_PROGRAM_ID,
            )

            await mintTo(
                this.common.connection,
                payer,
                mint,
                tokenAccount.address,
                tokenAuthority,
                config.initialSupply,
                [],
                undefined,
                TOKEN_PROGRAM_ID,
            )

            console.log(`Minted ${config.initialSupply.toString()} tokens to ${tokenAccount.address.toString()}`)
        }

        console.log(`Token deployed successfully: ${mint.toString()}`)
        return mint
    }
}
