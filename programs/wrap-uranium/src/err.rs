use anchor_lang::prelude::*;
#[error_code]
pub enum CustomError {
    YouAreNotAdmin,
    YouAreNotWrapAuthority,
    YouAreNotUnwrapAuthority,
    InvalidFee,
    InsufficientReserves,
}
