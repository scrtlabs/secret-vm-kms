// src/amd_attest.rs

use crate::error::ContractError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

// =============================================================================
// HARDCODED ROOT OF TRUST (ARK)
// =============================================================================

// Genoa ARK certificate (DER, base64-encoded).
// This is the absolute Root of Trust pinned in the contract.
const GENOA_ARK_DER_B64: &str = "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";

#[derive(Clone, Debug)]
pub struct VerifiedAmdReport {
    /// 48-byte measurement
    pub measurement: [u8; 48],
    /// 64-byte report_data
    pub report_data: [u8; 64],
    /// 64-byte chip_id
    pub chip_id: [u8; 64],
}

/// Attestation input.
/// Report, ASK, and VCEK are ALL MANDATORY.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AmdAttestationInput {
    /// Full SNP attestation report bytes, base64-encoded
    pub report_b64: String,
    /// Base64-encoded PEM string of the ASK (AMD Sev Key)
    pub ask_pem_b64: String,
    /// Base64-encoded PEM string of the VCEK (Versioned Chip Endorsement Key)
    pub vcek_pem_b64: String,
}

// Helper: Decode Base64 string
fn b64_decode(label: &str, s: &str) -> Result<Vec<u8>, ContractError> {
    STANDARD.decode(s.as_bytes()).map_err(|e| ContractError::AmdInvalidBase64 {
        field: label.to_string(),
        reason: e.to_string(),
    })
}

// Helper: Check hardcoded config
fn check_configured(name: &str, value: &str) -> Result<(), ContractError> {
    if value.starts_with("TODO") {
        return Err(ContractError::AmdVerifyFailed(format!(
            "{} not configured in contract. Update amd_attest.rs",
            name
        )));
    }
    Ok(())
}

/// Helper to parse a Base64-encoded PEM string into a Certificate
fn parse_cert_from_b64_pem(label: &str, b64_pem: &str) -> Result<Certificate, ContractError> {
    // 1. Decode Base64 to get the PEM string bytes
    let pem_bytes = b64_decode(label, b64_pem)?;
    // 2. Parse PEM bytes to Certificate using sev crate
    Certificate::from_pem(&pem_bytes)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Failed to parse {} PEM: {:?}", label, e)))
}

/// Main Verification Function
///
/// Workflow:
/// 1. Parse Report.
/// 2. Load Hardcoded ARK (Root of Trust).
/// 3. Parse provided ASK (PEM) and VCEK (PEM).
/// 4. Verify Chain: ARK -> ASK -> VCEK.
/// 5. Verify Report Signature: VCEK -> Report.
pub fn verify_amd_attestation(att: &AmdAttestationInput) -> Result<VerifiedAmdReport, ContractError> {
    // 1. Ensure ARK is configured in contract
    check_configured("ARK", GENOA_ARK_DER_B64)?;

    // 2. Parse the Attestation Report
    let report_bytes = b64_decode("report_b64", &att.report_b64)?;
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Report parse failed: {e}")))?;

    // 3. Load Hardcoded ARK (Root of Trust)
    let ark_der = b64_decode("ark", GENOA_ARK_DER_B64)?;
    let ark = Certificate::from_der(&ark_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("ARK parse failed: {e}")))?;

    // 4. Parse provided ASK and VCEK from PEM
    let ask = parse_cert_from_b64_pem("ask_pem", &att.ask_pem_b64)?;
    let vcek = parse_cert_from_b64_pem("vcek_pem", &att.vcek_pem_b64)?;

    // 5. Verify Certificate Chain (ARK -> ASK -> VCEK)
    let ca_chain = ca::Chain { ark, ask };
    let chain = Chain { ca: ca_chain, vek: vcek.clone() };

    chain.verify()
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Certificate chain verify failed: {e}")))?;

    // 6. Verify Report Signature using VCEK
    (&vcek, &report).verify()
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Report signature verify failed: {e}")))?;

    // 7. Extract Verified Data
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(report.report_data.as_ref());

    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(report.measurement.as_ref());

    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(report.chip_id.as_ref());

    Ok(VerifiedAmdReport {
        measurement,
        report_data,
        chip_id,
    })
}