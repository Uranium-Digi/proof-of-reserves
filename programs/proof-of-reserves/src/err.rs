use anchor_lang::prelude::*;

#[error_code]
pub enum CustomError {
    YouAreNotAdmin,
    YouAreNotUpdateAuthority,
    YouAreNotIssueAuthority,
    YouAreNotRedeemAuthority,
    YouAreNotPendingAuthority,
    NoPendingAuthority,
    InsufficientReserves,
    IssuanceFeeCalculationError,
    RedemptionFeeCalculationError,
    InvalidReportData,
    NoReportData,
    InvalidUtf8String,
    InvalidHexString,
    InvalidFeeRate,
    InvalidProgramId,
    ReportAlreadyVerified,
}
