use anchor_lang::{prelude::Result, solana_program::native_token::LAMPORTS_PER_SOL};
use err::CustomError;

use crate::err;

pub fn calculate_issuance_fee(gross_issue: u64, issuance_fee_rate: u64) -> Result<(u64, u64)> {
    let issuance_fee = gross_issue
        .checked_mul(issuance_fee_rate)
        .ok_or(CustomError::IssuanceFeeCalculationError)?
        .checked_div(10000)
        .ok_or(CustomError::IssuanceFeeCalculationError)?;
    // round off to the nearest token
    let issuance_fee = issuance_fee / LAMPORTS_PER_SOL * LAMPORTS_PER_SOL;
    let receivable = gross_issue
        .checked_sub(issuance_fee)
        .ok_or(CustomError::IssuanceFeeCalculationError)?;
    Ok((issuance_fee, receivable))
}

pub fn calculate_redemption_fee(gross_redeem: u64, redemption_fee_rate: u64) -> Result<(u64, u64)> {
    let redemption_fee = gross_redeem
        .checked_mul(redemption_fee_rate)
        .ok_or(CustomError::RedemptionFeeCalculationError)?
        .checked_div(10000)
        .ok_or(CustomError::RedemptionFeeCalculationError)?;
    // round off to the nearest token
    let redemption_fee = redemption_fee / LAMPORTS_PER_SOL * LAMPORTS_PER_SOL;
    let redeemable = gross_redeem
        .checked_sub(redemption_fee)
        .ok_or(CustomError::RedemptionFeeCalculationError)?;
    Ok((redemption_fee, redeemable))
}
