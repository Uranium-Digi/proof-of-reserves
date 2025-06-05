import { TokenDeployer } from './TokenDeployer'
import { Keypair, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js'
import Common from './Common'
import { TokenConfig } from './TokenDeployer'

export class TokenFactory {
    private tokenDeployer: TokenDeployer

    constructor(common: Common) {
        this.tokenDeployer = new TokenDeployer(common)
    }

    async deployToken(
        name: string = 'Lemon Cake',
        symbol: string = 'LEMON',
        uri: string = 'https://rhttps://github.com/Uranium-Digi/lemon-cake/blob/main/0978fe9e1d7932debba36c233b4e34c7.jpg',
        description: string = 'Lemon cakes are Sansas favourite',
        initialSupply: number = 0, // 100 tokens - we will scale this up by LAMPORTS_PER_SOL below.
        vanityAddress?: Keypair | null,
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
            vanityAddress: vanityAddress ? vanityAddress : undefined,
        }

        console.log(`Deploying token ${name} with supply of ${config.initialSupply}`)
        return this.tokenDeployer.deployToken(config) // returns the mint address
    }
}
