import fs from "fs";
import bs58 from "bs58";
import path from "path";

// function to read from the .env files and prepare the base58Key of the funding wallet and the token authority wallet
import * as dotenv from "dotenv";

dotenv.config();

function getBase58Keys() {
  const fundingWalletKey = process.env.FUNDING_WALLET_PRIVATE_KEY;
  const tokenAuthorityKey = process.env.TOKEN_AUTHORITY_PRIVATE_KEY;

  if (!fundingWalletKey || !tokenAuthorityKey) {
    throw new Error("Missing required private keys in .env file");
  }

  return {
    fundingWalletKey,
    tokenAuthorityKey,
  };
}

export const spitOutWallets = async () => {
  const { fundingWalletKey, tokenAuthorityKey } = getBase58Keys();
  const secretsDir = process.env.SECRETS_DIR || "../.secrets";

  for (const key of [fundingWalletKey, tokenAuthorityKey]) {
    const decodedKey = bs58.decode(key);
    const keyArray = Array.from(decodedKey);
    const name = key === fundingWalletKey ? "fundingWallet" : "tokenAuthority";

    if (!fs.existsSync(secretsDir)) {
      fs.mkdirSync(secretsDir, { recursive: true });
    }

    // if the wallets already exist do nothing
    const filePath = path.join(secretsDir, `${name}.json`);
    if (fs.existsSync(filePath)) {
      console.log(`${name} already exists, skipping...`);
      continue;
    }

    fs.writeFileSync(filePath, JSON.stringify(keyArray, null, 2));
    console.log("Key successfully converted and saved to", filePath);
  }
};

spitOutWallets();
