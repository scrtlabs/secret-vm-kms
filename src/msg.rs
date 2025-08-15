use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::state::FilterEntry;

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

/// Execute messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Create a new service (string ID + name)
    CreateService { service_id: String, name: String },
    /// Add an image filter to a service, with description
    AddImageToService { service_id: String, image_filter: MsgImageFilter, description: String },
    /// Remove an image filter matching the provided definition
    RemoveImageFromService { service_id: String, image_filter: MsgImageFilter },
    /// AddSecretKeyByImage adds a secret key for a given image.
    AddSecretKeyByImage { image_filter: MsgImageFilter },
    /// NEW: Add an env secret by image.
    AddEnvByImage { image_filter: MsgImageFilter, secrets_plaintext: String },
    AddDockerCredentialsByImage {
        image_filter: MsgImageFilter,
        username: String,
        password_plaintext: String,
    },
    /// NEW: add or update env secret for a service
    AddEnvByService { service_id: String, secrets_plaintext: String },
}

/// Query messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// GetService returns information of a service by its id.
    GetService { id: String },
    /// ListServices returns a list of all services.
    ListServices {},
    /// GetSecretKey returns the encrypted secret key for a service after verifying attestation.
    GetSecretKey { service_id: String, quote: Vec<u8>, collateral: Vec<u8> },
    /// Get secret key by image.
    GetSecretKeyByImage { quote: Vec<u8>, collateral: Vec<u8> },
    /// NEW: Get env secret by image.
    GetEnvByImage { quote: Vec<u8>, collateral: Vec<u8> },
    GetDockerCredentialsByImage {
        quote: Vec<u8>,
        collateral: Vec<u8>,
    },
    /// Return filters (with descriptions) for a service
    ListImageFilters { service_id: String },
    /// NEW: retrieve encrypted env secret for a service
    GetEnvByService { service_id: String, quote: Vec<u8>, collateral: Vec<u8> },
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
