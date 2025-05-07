import { Connection } from "@solana/web3.js";
import { RPC_URL } from "./config";

import * as anchor from "@coral-xyz/anchor";
import WalletManager from "./WalletManager";

export const connection = new Connection(RPC_URL, "confirmed");
export const anchorConnection = new anchor.web3.Connection(RPC_URL);

export const setUpAnchorProvider = async () => {
  const fundingWallet = await WalletManager.getFundingWallet();
  const wallet = new anchor.Wallet(fundingWallet);
  // Setup connection and provider
  const provider = new anchor.AnchorProvider(connection, wallet, {});
  anchor.setProvider(provider);
  return provider;
};
