use anchor_lang::prelude::*;
#[error_code]
pub enum CustomError {
    YouAreNotAdmin,
    YouAreNotWrapAuthority,
    YouAreNotUnwrapAuthority,
    YouAreNotMintAndWrapAuthority,
    YouAreNotUnwrapAndBurnAuthority,
    InvalidFee,
    InsufficientReserves,
    IssuanceFeeCalculationError,
    RedemptionFeeCalculationError,
}
