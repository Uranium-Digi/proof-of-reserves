// https://developers.metaplex.com/guides/javascript/how-to-create-a-solana-token
import {
    fetchMetadataFromSeeds,
    findMetadataPda,
    updateMetadataAccountV2,
} from '@metaplex-foundation/mpl-token-metadata'
import { createFungible } from '@metaplex-foundation/mpl-token-metadata'
import {
    createTokenIfMissing,
    findAssociatedTokenPda,
    getSplAssociatedTokenProgramId,
    mintTokensTo,
} from '@metaplex-foundation/mpl-toolbox'
import {
    generateSigner,
    percentAmount,
    KeypairSigner,
    PublicKey,
    publicKey,
    Umi,
    createSignerFromKeypair,
} from '@metaplex-foundation/umi'

import { base58 } from '@metaplex-foundation/umi/serializers'
import { setUpUmi } from '../config'
import { Keypair } from '@solana/web3.js'

export interface TokenConfig {
    name: string
    symbol: string
    imageUri: string
    description: string
    decimals: number
    initialSupply: bigint
    vanityAddress?: KeypairSigner | undefined
}

export default class MetaplexComplex {
    umi: Umi
    constructor() {
        this.umi = setUpUmi()
    }

    createTokenConfig = (
        name: string,
        symbol: string,
        description: string,
        imageUri: string,
        initialSupply?: bigint,
        vanityAddress?: KeypairSigner | undefined,
    ) => {
        const tokenConfig: TokenConfig = {
            name: name,
            symbol: symbol,
            description: description,
            imageUri: imageUri,
            decimals: 9,
            initialSupply: initialSupply || BigInt(0),
            vanityAddress: vanityAddress,
        }
        return tokenConfig
    }

    // We need this to conform to this https://docs.solscan.io/integration/update-token-details
    createAndMintTokensViaMetaplex = async (
        name: string = 'Lemon Cake',
        symbol: string = 'LEMON',
        description: string = 'This is a lemon cake.',
        imageUri: string = 'https://raw.githubusercontent.com/Uranium-Digi/lemon-cake/refs/heads/main/0978fe9e1d7932debba36c233b4e34c7.jpg',
        initialSupply: bigint = BigInt(0),
        vanityAddress?: KeypairSigner | undefined,
    ): Promise<KeypairSigner> => {
        // https://developers.metaplex.com/guides/javascript/how-to-create-a-solana-token
        const umi = await setUpUmi()

        const tokenConfig = this.createTokenConfig(name, symbol, description, imageUri, initialSupply, vanityAddress)

        // Airdrop 1 SOL to the identity
        // if you end up with a 429 too many requests error, you may have to use
        // the filesystem wallet method or change rpcs.
        // console.log('AirDrop 1 SOL to the umi identity')
        // await umi.rpc.airdrop(umi.identity.publicKey, sol(1))

        // Uploading the tokens metadata to Arweave via Irys

        const metadata = {
            name: tokenConfig.name,
            symbol: tokenConfig.symbol,
            description: tokenConfig.description,
            image: tokenConfig.imageUri, // Either use variable or paste in string of the uri.
        }

        // Call upon umi's uploadJson function to upload our metadata to Arweave via Irys.
        console.log('Uploading metadata to Arweave via Irys')
        const metadataUri = await umi.uploader.uploadJson(metadata).catch((err) => {
            throw new Error(err)
        })

        // Creating the mintIx
        let mintSigner: KeypairSigner
        if (tokenConfig.vanityAddress) {
            console.log('Using vanity address')
            mintSigner = tokenConfig.vanityAddress
        } else {
            console.log('Generating new mint signer')
            mintSigner = generateSigner(umi)
        }

        console.log('mintSigner:', mintSigner)
        console.log('metadataUri', metadataUri)

        const createFungibleIx = createFungible(umi, {
            mint: mintSigner,
            name: tokenConfig.name,
            symbol: tokenConfig.symbol,
            uri: metadataUri, // we use the `metadataUri` variable we created earlier that is storing our uri.
            sellerFeeBasisPoints: percentAmount(0),
            decimals: tokenConfig.decimals, // must be 9 - if 0 it's a fucking NFT
        })

        console.log('createFungibleIx', createFungibleIx)

        // This instruction will create a new Token Account if required, if one is found then it skips.

        const createTokenIx = createTokenIfMissing(umi, {
            mint: mintSigner.publicKey,
            owner: umi.identity.publicKey,
            ataProgram: getSplAssociatedTokenProgramId(umi),
        })

        console.log('createTokenIx', createTokenIx)

        // The final instruction (if required) is to mint the tokens to the token account in the previous ix.

        const mintTokensIx = mintTokensTo(umi, {
            mint: mintSigner.publicKey,
            token: findAssociatedTokenPda(umi, {
                mint: mintSigner.publicKey,
                owner: umi.identity.publicKey,
            }),
            amount: tokenConfig.initialSupply,
        })
        console.log('mintTokensIx', mintTokensIx)

        // The last step is to send the ix's off in a transaction to the chain.
        // Ix's here can be omitted and added as needed during the transaction chain.
        // If for example you just want to create the Token without minting
        // any tokens then you may only want to submit the `createToken` ix.

        console.log('Sending transaction')
        const tx = await createFungibleIx.add(createTokenIx).add(mintTokensIx).sendAndConfirm(umi)

        // finally we can deserialize the signature that we can check on chain.
        const signature = base58.deserialize(tx.signature)[0]

        // Log out the signature and the links to the transaction and the NFT.
        // Explorer links are for the devnet chain, you can change the clusters to mainnet.
        console.log('\nTransaction Complete')
        console.log('View Transaction on Solscan')
        console.log(`https://solscan.io/tx/${signature}?cluster=devnet`)
        console.log('View Token on Solscan')
        console.log(`https://solscan.io/address/${mintSigner.publicKey}?cluster=devnet`)
        return mintSigner
    }

    changeMetadata = async (
        tokenAddress: string,
        name: string = 'Lemon Cake',
        symbol: string = 'LEMON',
        description: string = 'This is a lemon cake.',
        imageUri: string = 'https://raw.githubusercontent.com/Uranium-Digi/lemon-cake/refs/heads/main/0978fe9e1d7932debba36c233b4e34c7.jpg',
    ) => {
        // https://developers.metaplex.com/guides/javascript/how-to-create-a-solana-token
        const umi = await setUpUmi()
        console.log('🔑 Umi signer (must be updateAuthority):', umi.identity.publicKey.toString())

        const tokenConfig = this.createTokenConfig(name, symbol, description, imageUri)
        const mint = publicKey(tokenAddress)

        const metadata = {
            name: tokenConfig.name,
            symbol: tokenConfig.symbol,
            description: tokenConfig.description,
            image: tokenConfig.imageUri,
        }

        const metadataUri = await umi.uploader.uploadJson(metadata)
        console.log('metadataUri', metadataUri)

        // Fetch existing on-chain metadata to preserve creators
        const existingMetadata = await fetchMetadataFromSeeds(umi, { mint })
        console.log('🧾 Existing metadata:', existingMetadata)
        console.log('🧾 Existing verified creators:', existingMetadata.creators)

        const metadataPda = findMetadataPda(umi, { mint: mint }) // use your token's mint address
        const tx = await updateMetadataAccountV2(umi, {
            metadata: metadataPda,
            updateAuthority: umi.identity, // must be current update authority
            data: {
                name: metadata.name,
                symbol: metadata.symbol,
                uri: metadataUri, // ← key field
                sellerFeeBasisPoints: 0,
                creators: existingMetadata.creators,
                collection: null,
                uses: null,
            },
            primarySaleHappened: null,
            isMutable: true, // keep it mutable or freeze it (false)
        }).sendAndConfirm(umi)
        console.log('tx.signature', tx.signature)
    }

    convertUmiKeypairSignerToAnchorKeypair = (umiKeypairSigner: KeypairSigner) => {
        return Keypair.fromSecretKey(umiKeypairSigner.secretKey)
    }

    convertAnchorKeypairToUmiKeypairSigner = (anchorKeypair: Keypair) => {
        let umiKeypair = this.umi.eddsa.createKeypairFromSecretKey(new Uint8Array(anchorKeypair.secretKey))
        const myKeypairSigner = createSignerFromKeypair(this.umi, umiKeypair)
        return myKeypairSigner
    }
}
