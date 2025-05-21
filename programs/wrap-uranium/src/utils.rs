use anchor_lang::prelude::{AccountInfo, Result};
use anchor_spl::token_2022::spl_token_2022::{
    extension::{
        transfer_fee::TransferFee, BaseStateWithExtensions, Extension, StateWithExtensions,
        
    },
    state::Mint,
};
use bytemuck::Pod;
use err::CustomError;

use crate::err;

pub fn get_mint_extension_data<T: Extension + Pod>(account: &mut AccountInfo) -> Result<T> {
    let mint_data = account.data.borrow();
    let mint_with_extension = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    let extension_data = *mint_with_extension.get_extension::<T>()?;
    Ok(extension_data)
}

pub fn calculate_transfer_amount(fee: &TransferFee, amount: u64) -> Result<(u64, u64)> {
    let ata = fee
        .calculate_post_fee_amount(amount)
        .ok_or(CustomError::InvalidFee)?;

    let amount_actually_from_ata = fee
        .calculate_post_fee_amount(ata)
        .ok_or(CustomError::InvalidFee)?;

    let diff = amount - amount_actually_from_ata;

    let reserve = fee
        .calculate_pre_fee_amount(diff)
        .ok_or(CustomError::InvalidFee)?;

    Ok((ata, reserve))
}

pub fn calculate_burn_amount(fee: &TransferFee, amount: u64) -> Result<(u64, u64)> {
    let ata = fee
        .calculate_post_fee_amount(amount)
        .ok_or(CustomError::InvalidFee)?;

    let reserve = fee.calculate_fee(amount).ok_or(CustomError::InvalidFee)?;

    assert_eq!(ata + reserve, amount);

    Ok((ata, reserve))
}
