import * as anchor from '@coral-xyz/anchor'

import { Connection, Keypair, PublicKey } from '@solana/web3.js'

export default class Common {
    connection: Connection
    provider: anchor.AnchorProvider
    fundingWallet: anchor.Wallet // this cannot be deleted because it is used for the anchorProvider
    // Define the genesis hashes as constants
    readonly TESTNET_GENESIS_HASH = '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY' // Testnet genesis hash
    readonly DEVNET_GENESIS_HASH = 'EtWTRABZaYqkW7QKBY59fHz9rGh5L7oAcyt8o3MiMJie' // Devnet genesis hash
    readonly MAINNET_GENESIS_HASH = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'

    constructor(connection: anchor.web3.Connection, fundingWalletKP: Keypair) {
        this.connection = connection
        this.fundingWallet = new anchor.Wallet(fundingWalletKP)

        const provider = new anchor.AnchorProvider(this.connection, this.fundingWallet, {})
        anchor.setProvider(provider)

        this.provider = provider
    }

    async checkCluster(connection: Connection): Promise<string> {
        const genesisHash = await connection.getGenesisHash()

        if (genesisHash === this.TESTNET_GENESIS_HASH) {
            console.log('genesisHash', genesisHash, 'testnet')
            return 'testnet'
        } else if (genesisHash === this.DEVNET_GENESIS_HASH) {
            console.log('genesisHash', genesisHash, 'devnet')
            return 'devnet'
        } else if (genesisHash === this.MAINNET_GENESIS_HASH) {
            console.log('genesisHash', genesisHash, 'mainet')
            return 'mainet'
        } else {
            return 'unknown'
        }
    }
}
