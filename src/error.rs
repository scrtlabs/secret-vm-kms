// src/error.rs (добавь ошибки)
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    // --- AMD attestation errors ---
    #[error("AMD attestation: invalid base64 in field '{field}': {reason}")]
    AmdInvalidBase64 { field: String, reason: String },

    #[error("AMD attestation: invalid length for '{field}', expected {expected}, got {got}")]
    AmdInvalidLen { field: String, expected: usize, got: usize },

    #[error("AMD attestation verification failed: {0}")]
    AmdVerifyFailed(String),

    #[error("AMD measurement mismatch")]
    AmdMeasurementMismatch {},

    #[error("AMD report_data mismatch")]
    AmdReportDataMismatch {},
}
