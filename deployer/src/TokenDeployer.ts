import {
    Keypair,
    PublicKey,
    SystemProgram,
    Transaction,
    sendAndConfirmTransaction,
    LAMPORTS_PER_SOL,
} from '@solana/web3.js'
import {
    createInitializeMetadataPointerInstruction,
    createInitializeMintInstruction,
    ExtensionType,
    getMintLen,
    getOrCreateAssociatedTokenAccount,
    TOKEN_2022_PROGRAM_ID,
    LENGTH_SIZE,
    TYPE_SIZE,
    mintTo,
} from '@solana/spl-token'
import { createInitializeInstruction, pack, TokenMetadata } from '@solana/spl-token-metadata'
import { ASSOCIATED_PROGRAM_ID } from '@coral-xyz/anchor/dist/cjs/utils/token'
import Common from './Common'
import WalletManager from './WalletManager'

export interface TokenConfig {
    name: string
    symbol: string
    uri: string
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

    async deployToken(config: TokenConfig): Promise<PublicKey> {
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

        const metadata: TokenMetadata = {
            mint,
            name: config.name,
            symbol: config.symbol,
            uri: config.uri,
            additionalMetadata: config.description ? [['description', config.description]] : [],
        }

        const metadataLen = TYPE_SIZE + LENGTH_SIZE + pack(metadata).length
        const extensions = [ExtensionType.MetadataPointer]

        const mintLen = getMintLen(extensions)
        const mintLamports = await this.common.connection.getMinimumBalanceForRentExemption(mintLen + metadataLen)

        const tx = new Transaction().add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: mint,
                space: mintLen,
                lamports: mintLamports,
                programId: TOKEN_2022_PROGRAM_ID,
            }),
            createInitializeMetadataPointerInstruction(mint, payer.publicKey, mint, TOKEN_2022_PROGRAM_ID),

            createInitializeMintInstruction(
                mint,
                config.decimals,
                tokenAuthority.publicKey,
                null,
                TOKEN_2022_PROGRAM_ID,
            ),
            createInitializeInstruction({
                programId: TOKEN_2022_PROGRAM_ID,
                mint,
                metadata: mint,
                name: metadata.name,
                symbol: metadata.symbol,
                uri: metadata.uri,
                mintAuthority: tokenAuthority.publicKey,
                updateAuthority: tokenAuthority.publicKey,
            }),
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
                TOKEN_2022_PROGRAM_ID,
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
                TOKEN_2022_PROGRAM_ID,
            )

            console.log(`Minted ${config.initialSupply.toString()} tokens to ${tokenAccount.address.toString()}`)
        }

        console.log(`Token deployed successfully: ${mint.toString()}`)
        return mint
    }
}
