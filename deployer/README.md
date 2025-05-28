# Token Deployer

A Solana token deployment tool for creating and managing SPL tokens.

### Usage

1. Run "yarn build:proto" to generate/regenerate the proto files
2. Run "ts-node src/index.ts" to start the server

### Build

1. Run "yarn build" to build the server

### Test

1. Run "npm run test --runInBand".

### Directory Structure

<!-- -->

This repo deploys the a fee-collecting token, intialling setting the fee to be 0, and then calls the dpeloyment of the wrap-uranium contract, supplies the wrap-uranium contract with the token address of the deployed token, and then calls "intiialize".

 <!-- and then migrates the tookenAuthority to an ultimate tokenAuthority.  -->
