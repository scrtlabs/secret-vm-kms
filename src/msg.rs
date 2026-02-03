use crate::state::FilterEntry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hardware register pair message (for execute messages)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HwRegisterPairMsg {
    pub mr_td: String, // hex string
    pub rtmr0: String, // hex string
}

/// Instantiate message for initializing the contract (currently no parameters)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

/// Structure representing an image filter for attestation verification.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MsgImageFilter {
    pub mr_seam: Option<Vec<u8>>,
    pub mr_signer_seam: Option<Vec<u8>>,
    pub mr_td: Option<Vec<u8>>,
    pub mr_config_id: Option<Vec<u8>>,
    pub mr_owner: Option<Vec<u8>>,
    pub mr_config: Option<Vec<u8>>,
    pub rtmr0: Option<Vec<u8>>,
    pub rtmr1: Option<Vec<u8>>,
    pub rtmr2: Option<Vec<u8>>,
    pub rtmr3: Option<Vec<u8>>,
    /// A unique identifier for the VM.  This must be supplied and will be included in key derivation.
    pub vm_uid: Option<Vec<u8>>,
}

/// AMD Image Filter: Currently just the measurement (digest) and vm_uid
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AmdMsgImageFilter {
    pub measurement: Option<Vec<u8>>,
    pub vm_uid: Option<Vec<u8>>,
}

/// Execute messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Create a new service (string ID + name)
    CreateService {
        service_id: String,
        name: String,
        password_hash: Option<String>,
    },
    /// Add an image filter to a service, with description
    AddImageToService {
        service_id: String,
        image_filter: MsgImageFilter,
        description: String,
        timestamp: Option<u64>,
    },
    /// Remove an image filter matching the provided definition
    RemoveImageFromService {
        service_id: String,
        image_filter: MsgImageFilter,
    },
    /// AddSecretKeyByImage adds a secret key for a given image.
    AddSecretKeyByImage {
        image_filter: MsgImageFilter,
        password_hash: Option<String>,
    },
    /// NEW: Add an env secret by image.
    AddEnvByImage {
        image_filter: MsgImageFilter,
        secrets_plaintext: String,
        password_hash: Option<String>,
    },
    AddDockerCredentialsByImage {
        image_filter: MsgImageFilter,
        username: String,
        password_plaintext: String,
    },
    AddEnvByService {
        service_id: String,
        secrets_plaintext: String,
    },

    // --- AMD NEW EXECUTE VARIANTS ---
    CreateAmdService {
        service_id: String,
        name: String,
        password_hash: Option<String>,
    },
    AddAmdImageToService {
        service_id: String,
        image_filter: AmdMsgImageFilter,
        description: String,
        timestamp: Option<u64>,
    },
    AddAmdEnvByService {
        service_id: String,
        secrets_plaintext: String,
    },
    AddAmdSecretKeyByImage {
        image_filter: AmdMsgImageFilter,
        password_hash: Option<String>,
    },
    AddAmdEnvByImage {
        image_filter: AmdMsgImageFilter,
        secrets_plaintext: String,
        password_hash: Option<String>,
    },
    AddAmdDockerCredentialsByImage {
        image_filter: AmdMsgImageFilter,
        username: String,
        password_plaintext: String,
    },
    // --- TEST HANDLER (UPDATED) ---
    /// Test endpoint to verify an AMD report during execution.
    /// Now requires certificates (ASK and VCEK) in PEM format (Base64 encoded).
    TestAmdVerification {
        report: String,
        ask_pem: String,
        vcek_pem: String,
    },

    // --- TDX HW REGISTERS WHITELIST ---
    /// Add multiple hardware register pairs (mr_td, rtmr0) to whitelist
    AddHwRegistersToWhitelist { pairs: Vec<HwRegisterPairMsg> },
    /// Remove multiple hardware register pairs from whitelist
    RemoveHwRegistersFromWhitelist { pairs: Vec<HwRegisterPairMsg> },
}

/// Query messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// GetService returns information of a service by its id.
    GetService {
        id: String,
    },
    /// ListServices returns a list of all services.
    ListServices {},
    /// GetSecretKey returns the encrypted secret key for a service after verifying attestation.
    /// password is optional (not required for legacy/records without a password)
    GetSecretKey {
        service_id: String,
        quote: Vec<u8>,
        collateral: Vec<u8>,
        password: Option<String>,
    },
    /// Get secret key by image.
    GetSecretKeyByImage {
        quote: Vec<u8>,
        collateral: Vec<u8>,
        password: Option<String>,
    },
    /// NEW: Get env secret by image.
    GetEnvByImage {
        quote: Vec<u8>,
        collateral: Vec<u8>,
        password: Option<String>,
    },
    GetDockerCredentialsByImage {
        quote: Vec<u8>,
        collateral: Vec<u8>,
    },
    /// Return filters (with descriptions) for a service
    ListImageFilters {
        service_id: String,
    },
    GetEnvByService {
        service_id: String,
        quote: Vec<u8>,
        collateral: Vec<u8>,
        password: Option<String>,
    },

    // --- AMD QUERY VARIANTS ---
    /// Get AMD Service Info
    GetAmdService {
        id: String,
    },
    /// List AMD Services
    ListAmdServices {},
    /// List AMD Filters for a service
    ListAmdImageFilters {
        service_id: String,
    },

    // Verification Queries
    GetSecretKeyAmd {
        service_id: String,
        report: String,
        ask_pem: String,
        vcek_pem: String,
        password: Option<String>,
    },
    GetSecretKeyByImageAmd {
        report: String,
        ask_pem: String,
        vcek_pem: String,
        password: Option<String>,
    },
    GetEnvByImageAmd {
        report: String,
        ask_pem: String,
        vcek_pem: String,
        password: Option<String>,
    },
    GetDockerCredentialsByImageAmd {
        report: String,
        ask_pem: String,
        vcek_pem: String,
    },
    GetEnvByServiceAmd {
        service_id: String,
        report: String,
        ask_pem: String,
        vcek_pem: String,
        password: Option<String>,
    },

    // --- TDX HW REGISTERS WHITELIST QUERIES ---
    /// Get all hardware register pairs from whitelist
    GetAllHwRegisters {},
    /// Check if specific hardware register pair exists in whitelist
    CheckHwRegisterPair {
        mr_td: String,
        rtmr0: String,
    },
}

/// Migrate message enum for contract migration.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ServiceResponse {
    pub id: String,
    pub name: String,
    pub admin: String,
}

/// Typed response for hex-encoded filters
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageFilterHexEntry {
    pub filter: ImageFilterHex,
    pub description: String,
    pub timestamp: Option<u64>,
}

/// Single filter hex struct
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageFilterHex {
    pub mr_seam: Option<String>,
    pub mr_signer_seam: Option<String>,
    pub mr_td: Option<String>,
    pub mr_config_id: Option<String>,
    pub mr_owner: Option<String>,
    pub mr_config: Option<String>,
    pub rtmr0: Option<String>,
    pub rtmr1: Option<String>,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
}

/// Response wrapper for listing filters
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ListImageResponse {
    pub service_id: String,
    pub filters: Vec<ImageFilterHexEntry>,
}

/// Response for GetSecretKey.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SecretKeyResponse {
    pub encrypted_secret_key: String,
    pub encryption_pub_key: String, // New field to return the public key used in encryption.
}

/// NEW: Response for GetEnvByImage.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct EnvSecretResponse {
    pub encrypted_secrets_plaintext: String,
    pub encryption_pub_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct DockerCredentialsResponse {
    pub encrypted_username: String,
    pub encrypted_password: String,
    pub encryption_pub_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AmdAttestation {
    // Base64 of full SNP attestation report bytes
    pub report_b64: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AmdListImageResponse {
    pub service_id: String,
    pub filters: Vec<AmdImageFilterHexEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AmdImageFilterHexEntry {
    pub measurement: Option<String>,
    pub description: String,
    pub timestamp: Option<u64>,
}

/// Response for GetAllHwRegisters query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HwRegistersWhitelistResponse {
    pub pairs: Vec<HwRegisterPairMsg>,
}

/// Response for CheckHwRegisterPair query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HwRegisterPairCheckResponse {
    pub exists: bool,
}
