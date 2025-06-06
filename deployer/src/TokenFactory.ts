import { TokenDeployer } from './TokenDeployer'
import { LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js'
import Common from './Common'
import { TokenConfig } from './TokenDeployer'

export class TokenFactory {
    private tokenDeployer: TokenDeployer

    // Standard fee configurations
    private static readonly FEE_CONFIGS = {
        NONE: {
            feeBasisPoints: 0,
            maxFee: BigInt(100_000_000_000 * LAMPORTS_PER_SOL), // 100 million SOL - an ungodly amount
        },
        HIGH: {
            feeBasisPoints: 20, // 20 bips
            maxFee: BigInt(100_000_000_000 * LAMPORTS_PER_SOL), // 100 million SOL - an ungodly amount
        },
    }

    constructor(common: Common) {
        this.tokenDeployer = new TokenDeployer(common)
    }

    async deployToken(
        name: string = 'Token',
        symbol: string = 'T',
        uri: string = 'https://raw.githubusercontent.com/solana-developers/opos-asset/main/assets/CompressedCoil/image.png',
        description: string = 'This is a token implementation',
        withFees: boolean = false,
        initialSupply: number = 100, // 100 tokens - we will scale this up by LAMPORTS_PER_SOL below.
    ): Promise<PublicKey> {
        const network = await this.tokenDeployer.common.checkCluster(this.tokenDeployer.common.connection)
        if (network === 'mainnet') {
            throw new Error('Token deployment not allowed on mainnet')
        }

        const config: TokenConfig = {
            name: name,
            symbol: symbol.toUpperCase(),
            uri: uri, // No image
            description: description,
            decimals: 9,
            initialSupply: BigInt(initialSupply * LAMPORTS_PER_SOL),
            feeConfig: withFees ? TokenFactory.FEE_CONFIGS.HIGH : TokenFactory.FEE_CONFIGS.NONE,
        }

        console.log(
            `Deploying token ${name} with supply of ${config.initialSupply} and ${withFees ? 'with' : 'without'} fees`,
        )
        return this.tokenDeployer.deployToken(config) // returns the mint address
    }
}
