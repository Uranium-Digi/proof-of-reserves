use anchor_lang::prelude::*;

#[event]
pub struct RedeemEvent {
    pub gross_redeem: u64,
    pub redemption_fee: u64,
    pub redemption_id: String,
    pub created_at: i64,
}

#[event]
pub struct IssueEvent {
    pub gross_issue: u64,
    pub issuance_fee: u64,
    pub issuance_id: String,
    pub created_at: i64,
}

#[event]
pub struct VerifyEvent {
    pub total_reserves: u64,
    pub total_reserves_prev: u64,
    pub total_supply: u64,
    pub created_at: i64,
}
