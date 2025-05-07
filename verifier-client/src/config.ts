import path from "path";
import { Connection, PublicKey } from "@solana/web3.js";
import * as dotenv from "dotenv";
import * as anchor from "@coral-xyz/anchor";

// Load environment variables from .env file
dotenv.config();

// Directory paths
export const DIRECTORIES = {
  FUNDING_WALLET_FILE: process.env.FUNDING_WALLET_PATH || "",
  TOKEN_AUTHORITY_FILE: process.env.TOKEN_AUTHORITY_PATH || "",
};

export const NETWORK_USED: string = process.env.NETWORK_USED || "devnet";
// export const NETWORK_USED: string = 'devnet' // 'testnet' | 'mainnet' | 'devnet'

export const RPC_URL =
  NETWORK_USED === "testnet"
    ? process.env.TESTNET_PUBLIC_RPC_URL || "https://api.testnet.solana.com"
    : NETWORK_USED === "devnet"
    ? process.env.DEVNET_PUBLIC_RPC_URL ||
      process.env.DEVNET_RPC_URL ||
      "https://api.devnet.solana.com"
    : NETWORK_USED === "mainnet"
    ? process.env.MAINNET_PUBLIC_RPC_URL ||
      "https://api.mainnet-beta.solana.com"
    : "https://api.devnet.solana.com"; // use devnet as fallback
