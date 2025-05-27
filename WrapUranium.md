# Wrap-Uranium Program Function Reference

This document describes the on-chain functions (instructions) exposed by the wrap_uranium program. Each function governs minting, burning, wrapping, and authority management for the Uranium and Wrapped Uranium token pair.

## 1. initialize

Initializes the Config account and related program state for a given Uranium mint.

Sets the signer as config.authority, wrap_authority, and unwrap_authority

Initializes the wrapped_mint, mint_ata, and fee_rebate_reserve

Who can call: anyone (only once per mint)

## 2. set_app_config

Updates logical authorities stored in the Config account.

config.authority: admin

wrap_authority: allowed to call wrap, mint_and_wrap

unwrap_authority: allowed to call unwrap, unwrap_and_burn

Who can call: current config.authority

## 3. wrap

Wraps base Uranium tokens into Wrapped Uranium tokens.

Transfers mint tokens from user to config custody

Mints equal amount of wrapped_mint tokens to destination

Who can call: wrap_authority

## 4. unwrap

Unwraps Wrapped Uranium tokens back into Uranium tokens.

Burns wrapped_mint from user

Transfers mint tokens back to user, subtracting any transfer fee

Who can call: unwrap_authority

## 5. mint_and_wrap

Mints new Uranium and Wrapped Uranium tokens, subject to Proof of Reserves.

Checks that new supply does not exceed reserves

Mints Uranium to config.mint_ata

Mints wrapped tokens to recipient

Who can call: wrap_authority

## 6. unwrap_and_burn

Unwraps and burns tokens to reduce supply, accounting for fee mechanics.

Burns wrapped_mint from user

Transfers Uranium to user, split from mint_ata and fee_rebate_reserve

Burns equivalent Uranium supply from program reserves

Who can call: unwrap_authority

## 7. deposit_mint_authority

Transfers mint authority of the base Uranium token to the program's config PDA.

Required to enable programmatic minting via mint_and_wrap

Who can call: current mint authority (e.g., deployer)

## 8. withdraw_mint_authority

Transfers mint authority of the base Uranium token back to a signer wallet.

Used for emergency migration or handoff

Who can call: config.authority

## 9. deposit_wraped_mint_authority

Transfers mint authority of wrapped_mint to the program (the config PDA).

Only useful if wrapped_mint was manually created outside of the program

Who can call: current mint authority of wrapped_mint

## 10. withdraw_wraped_mint_authority

Transfers mint authority of wrapped_mint from the program to a signer.

Used if wrapped minting is to be handed off to another contract or off-chain controller

Who can call: config.authority

# Set up pipeliine

1. Deploy U token with `tokenAuthority`, set mint authority to be `tokenAuthority` (deployer)
2. Deploy `wrap_uranium` program.
3. Call `initialize` on `wrap_uranium` - sets the authority, wrap_authority, and unwrap_authority. But this does not actually give the `wrap_uranium` program the right to mint U tokens. We do that in the next step.
4. Call `deposit_mint_authority` with `tokenAuthority` on the `wrap_uranium` program. This is a CPI to the U token's `set_authority` function. Function call would fail, if the caller is not the current authority of the U token, which is `tokenAuthority` at the moment. After calling this, the `wrap_uranium` program would have U token minting rights.

# Difference between set_app_config and deposit_mint_authority, withdraw_mint_authority, and deposit_wrapped_mint_authority, withdraw_wrapped_mint_authority

## Authority Management

The program has two types of authority management:

1. **Program Configuration** (`set_app_config`)

   - Updates who can perform different actions in the program
   - Changes the stored authority addresses in the Config account
   - Controls: main authority, wrap authority, and unwrap authority
   - Like changing admin access to the program

2. **Mint Authority** (`deposit_mint_authority`, `withdraw_mint_authority`, `deposit_wrapped_mint_authority`, `withdraw_wrapped_mint_authority`)
   - Changes who can actually mint new tokens
   - Controls the mint authority of the token mints themselves
   - Two separate sets for original and wrapped tokens
   - Like changing who has the keys to mint tokens

This separation ensures that:

- Program access control is managed separately from token minting authority
- Original and wrapped tokens can have different minting authorities
- Authorities can be transferred between signers and the program's config PDA
