use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

/// Execute messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// CreateService creates a new service with the provided name.
    CreateService { name: String },
    /// AddImageToService adds an image filter to a service (only the service admin can call).
    AddImageToService { service_id: u64, image_filter: MsgImageFilter },
    /// RemoveImageFromService removes an image filter from a service (only the service admin can call).
    RemoveImageFromService { service_id: u64, image_filter: MsgImageFilter },
    /// AddSecretKeyByImage adds a secret key for a given image.
    AddSecretKeyByImage { image_filter: MsgImageFilter },
    /// NEW: Add an env secret by image.
    AddEnvByImage { image_filter: MsgImageFilter, secrets_plaintext: String },
}

/// Query messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// GetService returns information of a service by its id.
    GetService { id: u64 },
    /// ListServices returns a list of all services.
    ListServices {},
    /// GetSecretKey returns the encrypted secret key for a service after verifying attestation.
    GetSecretKey { service_id: u64, quote: Vec<u8>, collateral: Vec<u8> },
    /// Get secret key by image.
    GetSecretKeyByImage { quote: Vec<u8>, collateral: Vec<u8> },
    /// NEW: Get env secret by image.
    GetEnvByImage { quote: Vec<u8>, collateral: Vec<u8> },
}

/// Migrate message enum for contract migration.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

/// Response for service queries.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ServiceResponse {
    pub id: u64,
    pub name: String,
    pub admin: String,
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
    pub secrets_plaintext: String,
}
