// src/msg.rs
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Instantiate message for initializing the contract (currently no parameters)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

/// Structure representing a stub for ImageInfo with fixed variables.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageInfo {
    pub var1: String,
    pub var2: String,
    pub var3: String,
}

/// Structure representing a stub for attestation.
/// Additional fields can be added as requirements are finalized.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Attestation {
    /// Placeholder for ephemeral key or report data used for encryption.
    pub report_data: String,
}

/// Execute messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// CreateService creates a new service with the provided name.
    CreateService { name: String },
    /// AddImageToService adds image info to a service.
    /// Only the service admin can call this.
    AddImageToService { service_id: u64, image_info: ImageInfo },
    /// RemoveImageFromService removes image info from a service.
    /// Only the service admin can call this.
    RemoveImageFromService { service_id: u64, image_info: ImageInfo },
    /// GetSecretKey returns the encrypted secret key if the attestation is valid.
    GetSecretKey { service_id: u64, attestation: Attestation },
}

/// Query messages for the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// GetService returns information of a service by its id.
    GetService { id: u64 },
    /// ListServices returns a list of all services.
    ListServices {},
}

/// Response for service queries.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ServiceResponse {
    pub id: u64,
    pub name: String,
    pub admin: String,
}
