// import { connection } from './config'
// import Common from './Common'
// import WalletManager from './WalletManager'
// import { TokenFactory } from './TokenFactory'
// import { spitOutWallets } from './convertKey'
// export async function main() {
//     // let's get the wallets going
//     spitOutWallets()

//     const fundingWallet = await WalletManager.getFundingWallet()
//     const common = new Common(connection, fundingWallet)
//     const tokenFactory = new TokenFactory(common)

//     // Deploy a shitcoin
//     const shitcoin = await tokenFactory.deployShitcoin('Great Test Shit', 'gtSHIT', false)
//     console.log('Shitcoin deployed:', shitcoin.toString())

//     // Deploy a stablecoin
//     const stablecoin = await tokenFactory.deployStablecoin('Great Test USD Circle', 'gtUSDC')
//     console.log('Stablecoin deployed:', stablecoin.toString())
// }

// main().catch(console.error)
