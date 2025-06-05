use anchor_lang::prelude::*;

#[error_code]
pub enum CustomError {
    YouAreNotAdmin,
    YouAreNotIssueAuthority,
    YouAreNotRedeemAuthority,
    InsufficientReserves,
    IssuanceFeeCalculationError,
    RedemptionFeeCalculationError,
    InvalidReportData,
    NoReportData,
    InvalidUtf8String,
    InvalidHexString,
}
