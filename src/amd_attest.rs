// src/amd_attest.rs
//
// AMD SEV-SNP Attestation Verification
//
// ALL certificates are HARDCODED:
// - ARK (static per CPU generation)
// - ASK (static per CPU generation)
// - VCEK (static per physical CPU + TCB version)
//
// VCEK is the same for ALL VMs on the same physical host!
// It only changes if the host's TCB (firmware) is updated.

use crate::error::ContractError;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

// =============================================================================
// HARDCODED CERTIFICATES
// =============================================================================

// IMPORTANT: VCEK is unique per physical CPU. If you add more hosts,
// you'll need to add their VCEKs here

// ------------------ GENOA CERTIFICATES ------------------

/// Genoa ARK certificate (DER, base64-encoded)
const GENOA_ARK_DER_B64: &str = "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";
/// Genoa ASK certificate (DER, base64-encoded)
const GENOA_ASK_DER_B64: &str = "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";

/// Genoa VCEK certificate for Host #1 (DER, base64-encoded)
const GENOA_VCEK_HOST1_DER_B64: &str = "MIIFPzCCAvOgAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwezEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmljZXMxEjAQBgNVBAMMCVNFVi1HZW5vYTAeFw0yNTEyMjUwNDQyNDZaFw0zMjEyMjUwNDQyNDZaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkNFSzB2MBAGByqGSM49AgEGBSuBBAAiA2IABBGaNwJcUQ9xifrpCH0wrhIhnmGQW/m9B4GffjTkzHLpc2GPevF7XsDAOCDJshZnzrPPmo3BnaY/30jzMov+P9FTe3KnhSWgxTHifXkjPg7mxKljbNJTmz6SpwwxwE40ZaOCARMwggEPMBAGCSsGAQQBnHgBAQQDAgEAMBQGCSsGAQQBnHgBAgQHFgVHZW5vYTARBgorBgEEAZx4AQMBBAMCAQkwEQYKKwYBBAGceAEDAgQDAgEAMBEGCisGAQQBnHgBAwQEAwIBADARBgorBgEEAZx4AQMFBAMCAQAwEQYKKwYBBAGceAEDBgQDAgEAMBEGCisGAQQBnHgBAwcEAwIBADARBgorBgEEAZx4AQMDBAMCARcwEQYKKwYBBAGceAEDCAQDAgFIME0GCSsGAQQBnHgBBARAr3B06qTuhU/gShr0hF9iZF2tmIPzDUWz2KpH5bYJk6NoDE6wqOlFw/ZTJACbcRP1t+02Bifzy/lpYmOzWFpiozBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATADggIBAHci7MqmEUXLMTykM2J9z/Ooe3FW0R6a7T+d8NtsHQeIQfI+9HJlo3fYS0m15dhwHmRfAOQmA++2oe2qFi2lj5oPrsfde1EovED76EqxiOEyi/PVTJR+vC9BYPGb9RHHKeLnJbPN1kwxtqaHmQRiW6x1fa3Gjzw089cmzc7ZHNX0YG36mLP8+ozxxVpM+5/zMvlsluONPlORzWCNESUlkghU9nwHa35qoZgQ9v2h2UN3Go5Jf4iojtArBrHVWRjLTHSAl2RwvPnGetCiNfMQXnPpj6f9IxoHodJYG1KaAfLaQuScwsfi2PkcglYW0QaJK8bOhCfWnZXVYfUbhEeZKyB3vwcB0Deq5Bp8jYafEpKdxp27OQisoR8Zjdh4BEc8r9dIbpv9+7xldyRfSHYpLaeDPgTk9xbKrU/iHs1feQdZfrGxo9WeGeEUyU8S6K8nQnX95CZ0Yp+bnJl2bmUoLxzRluC0ROA7sxgXM6XWVz5fio8a2C3qbVhZhH0OLsEGHC/v2twvP98rxmyYqz1oa743bDZgSCPZfakkZw6oJzkb7k4x8p1kUDr08mRurV98doII9gLWDf/2qGTGRzHkv55+T0lggCeGYBmeKAPG+loaatr6RYadd5PIkFQa6wAE0NW/PuFHEveC/5JOITD8njxjqJ0UJhaXoC+MQ8TGNznm";

// Add more VCEKs for additional hosts:
// const GENOA_VCEK_HOST2_DER_B64: &str = "...";
// const GENOA_VCEK_HOST3_DER_B64: &str = "...";

// List of all known VCEKs (for lookup)
const GENOA_VCEKS: &[&str] = &[
    GENOA_VCEK_HOST1_DER_B64,
    // GENOA_VCEK_HOST2_DER_B64,
    // GENOA_VCEK_HOST3_DER_B64,
];

// =============================================================================
// TYPES
// =============================================================================

#[derive(Clone, Debug)]
pub struct VerifiedAmdReport {
    /// 48-byte measurement (SHA-384 of guest memory at launch)
    pub measurement: [u8; 48],
    /// 64-byte report_data (first 32 = pubkey, bytes 32-48 = vm_uid)
    pub report_data: [u8; 64],
    /// 64-byte chip_id (unique per physical CPU)
    pub chip_id: [u8; 64],
}

// =============================================================================
// SIMPLIFIED INPUT - ONLY REPORT NEEDED!
// =============================================================================

/// Minimal attestation input - ONLY the report is required!
/// All certificates are hardcoded in the contract.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AmdAttestationMinimal {
    /// Full SNP attestation report bytes, base64-encoded (1184 bytes)
    pub report_b64: String,
}

// =============================================================================
// HELPERS
// =============================================================================

fn b64_decode(label: &str, s: &str) -> Result<Vec<u8>, ContractError> {
    STANDARD.decode(s.as_bytes()).map_err(|e| ContractError::AmdInvalidBase64 {
        field: label.to_string(),
        reason: e.to_string(),
    })
}

fn check_configured(name: &str, value: &str) -> Result<(), ContractError> {
    if value.starts_with("TODO") {
        return Err(ContractError::AmdVerifyFailed(format!(
            "{} not configured. Update amd_attest.rs",
            name
        )));
    }
    Ok(())
}

/// Try to verify report with a list of known VCEKs
/// Returns the first one that successfully verifies
fn try_verify_with_vceks(
    report: &AttestationReport,
    ark: &Certificate,
    ask: &Certificate,
    vcek_b64_list: &[&str],
) -> Result<Certificate, ContractError> {
    for (i, vcek_b64) in vcek_b64_list.iter().enumerate() {
        if vcek_b64.starts_with("TODO") {
            continue;
        }

        let vcek_der = match b64_decode(&format!("vcek_{}", i), vcek_b64) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let vcek = match Certificate::from_der(&vcek_der) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Build chain and verify
        let ca_chain = ca::Chain { ark: ark.clone(), ask: ask.clone() };
        let chain = Chain { ca: ca_chain, vek: vcek.clone() };

        if chain.verify().is_err() {
            continue;
        }

        // Verify report signature
        if (&vcek, report).verify().is_ok() {
            return Ok(vcek);
        }
    }

    Err(ContractError::AmdVerifyFailed(
        "No matching VCEK found. Report may be from an unknown host.".to_string()
    ))
}

// =============================================================================
// MAIN VERIFICATION
// =============================================================================

/// Verify AMD SEV-SNP attestation with ALL certificates hardcoded
/// Client only needs to send the report!
pub fn verify_amd_attestation(att: &AmdAttestationMinimal) -> Result<VerifiedAmdReport, ContractError> {
    // 1. Check certificates are configured
    check_configured("ARK", GENOA_ARK_DER_B64)?;
    check_configured("ASK", GENOA_ASK_DER_B64)?;

    // 2. Decode report
    let report_bytes = b64_decode("report_b64", &att.report_b64)?;

    // 3. Parse attestation report
    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Report parse failed: {e}")))?;

    // 4. Load hardcoded ARK and ASK
    let ark_der = b64_decode("ark", GENOA_ARK_DER_B64)?;
    let ask_der = b64_decode("ask", GENOA_ASK_DER_B64)?;

    let ark = Certificate::from_der(&ark_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("ARK parse failed: {e}")))?;
    let ask = Certificate::from_der(&ask_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("ASK parse failed: {e}")))?;

    // 5. Try all known VCEKs to find one that verifies this report
    let _vcek = try_verify_with_vceks(&report, &ark, &ask, GENOA_VCEKS)?;

    // 6. Extract verified data
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

// =============================================================================
// ALTERNATIVE: Client provides VCEK (for unknown hosts)
// =============================================================================

/// Attestation with client-provided VCEK (for hosts not yet in hardcoded list)
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AmdAttestationWithVcek {
    pub report_b64: String,
    pub vcek_der_b64: String,
}

/// Verify with client-provided VCEK (ARK/ASK still hardcoded)
pub fn verify_amd_attestation_with_vcek(att: &AmdAttestationWithVcek) -> Result<VerifiedAmdReport, ContractError> {
    check_configured("ARK", GENOA_ARK_DER_B64)?;
    check_configured("ASK", GENOA_ASK_DER_B64)?;

    let report_bytes = b64_decode("report_b64", &att.report_b64)?;
    let vcek_der = b64_decode("vcek_der_b64", &att.vcek_der_b64)?;

    let report = AttestationReport::from_bytes(&report_bytes)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Report parse failed: {e}")))?;

    let ark_der = b64_decode("ark", GENOA_ARK_DER_B64)?;
    let ask_der = b64_decode("ask", GENOA_ASK_DER_B64)?;

    let ark = Certificate::from_der(&ark_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("ARK parse failed: {e}")))?;
    let ask = Certificate::from_der(&ask_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("ASK parse failed: {e}")))?;
    let vcek = Certificate::from_der(&vcek_der)
        .map_err(|e| ContractError::AmdVerifyFailed(format!("VCEK parse failed: {e}")))?;

    // Verify chain
    let ca_chain = ca::Chain { ark, ask };
    let chain = Chain { ca: ca_chain, vek: vcek.clone() };

    chain.verify()
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Cert chain verify failed: {e}")))?;

    // Verify report
    (&vcek, &report).verify()
        .map_err(|e| ContractError::AmdVerifyFailed(format!("Report signature verify failed: {e}")))?;

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(report.report_data.as_ref());

    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(report.measurement.as_ref());

    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(report.chip_id.as_ref());

    Ok(VerifiedAmdReport { measurement, report_data, chip_id })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------ TEST DATA ------------------

    /// Test report (base64-encoded)
    const TEST_REPORT_B64: &str = "AwAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAJAAAAAAAXSCcAAAAAAAAAAAAAAAAAAAACeDeESh3+s2BOgyl00cecxRfl4tTUlYiJZD4XcWD+NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARfzwClvAiI9FHN2uy6mp94NUPnKzGeFN84jIKj3Ou9NIsLDFrvIsVDLmXImX/m/GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiVRLNzxQCo/Ld3rkBXFn9U7kSgO4TOP8AKnqTleNnk///////////////////////////////////////////CQAAAAAAF0gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAACvcHTqpO6FT+BKGvSEX2JkXa2Yg/MNRbPYqkfltgmTo2gMTrCo6UXD9lMkAJtxE/W37TYGJ/PL+WliY7NYWmKjCQAAAAAAF0gnNwEAJzcBAAkAAAAAABdIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmvkwlMgGTaEGGO7x1whLf5hbvXDwNp514Rnc/70W779+Yi5iPS3cR0K5n3EmA+siAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATV33Rm6swqfKHv4N9neM7/9lWog7vxhygd0awl1XQrSP0IT9PqMJ6rD1dphA5ff8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// Expected measurement from this report (hex)
    const TEST_MEASUREMENT_HEX: &str = "45fcf00a5bc0888f451cddaecba9a9f783543e72b319e14df388c82a3dcebbd348b0b0c5aef22c5432e65c8997fe6fc6";

    // -----------------------------------------------

    #[test]
    fn test_verify_hardcoded_report() {
        // Skip if not configured
        if TEST_REPORT_B64.starts_with("TODO") {
            println!("Skipping test - not configured.");
            return;
        }

        let att = AmdAttestationMinimal {
            report_b64: TEST_REPORT_B64.to_string(),
        };

        let result = verify_amd_attestation(&att);

        match result {
            Ok(verified) => {
                let measurement_hex = hex::encode(&verified.measurement);
                println!("✓ Verification successful!");
                println!("  Measurement: {}", measurement_hex);
                println!("  Report data: {}", hex::encode(&verified.report_data));
                println!("  Chip ID: {}", hex::encode(&verified.chip_id));

                // Check measurement matches expected
                if !TEST_MEASUREMENT_HEX.starts_with("TODO") {
                    assert_eq!(
                        measurement_hex.to_lowercase(),
                        TEST_MEASUREMENT_HEX.to_lowercase(),
                        "Measurement mismatch!"
                    );
                    println!("  ✓ Measurement matches expected value");
                }
            }
            Err(e) => {
                panic!("Verification failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_parse_report_structure() {
        if TEST_REPORT_B64.starts_with("TODO") {
            println!("Skipping - not configured");
            return;
        }

        let report_bytes = STANDARD.decode(TEST_REPORT_B64).expect("decode report");
        let report = AttestationReport::from_bytes(&report_bytes).expect("parse report");

        println!("Report parsed successfully:");
        println!("  Version: {:?}", report.version);
        println!("  Guest SVN: {:?}", report.guest_svn);
        println!("  Policy: {:?}", report.policy);
        println!("  Measurement: {}", hex::encode(report.measurement.as_ref()));
        println!("  Report data: {}", hex::encode(report.report_data.as_ref()));
        println!("  Chip ID: {}", hex::encode(report.chip_id.as_ref()));
    }

    #[test]
    fn test_report_data_structure() {
        if TEST_REPORT_B64.starts_with("TODO") {
            println!("Skipping - not configured");
            return;
        }

        let report_bytes = STANDARD.decode(TEST_REPORT_B64).expect("decode report");
        let report = AttestationReport::from_bytes(&report_bytes).expect("parse report");

        let report_data = report.report_data.as_ref();

        // For Secret VM, report_data structure is:
        // [0..32]  = public key (32 bytes)
        // [32..48] = vm_uid (16 bytes)
        // [48..64] = padding/unused

        let pubkey = &report_data[0..32];
        let vm_uid = &report_data[32..48];

        println!("Report data breakdown:");
        println!("  Public key (32 bytes): {}", hex::encode(pubkey));
        println!("  VM UID (16 bytes): {}", hex::encode(vm_uid));

        // VM UID should not be all zeros (unless not set)
        let is_zero = vm_uid.iter().all(|&b| b == 0);
        if is_zero {
            println!("  Note: VM UID is all zeros");
        }
    }
}