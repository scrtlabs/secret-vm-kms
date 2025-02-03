// src/state.rs
use cosmwasm_std::{Addr, StdResult, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

static GLOBAL_STATE_KEY: &[u8] = b"global_state";
static SERVICES_KEY: &[u8] = b"services";

/// Global state of the contract which tracks the number of created services.
/// This counter is also used to generate new service IDs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GlobalState {
    pub service_count: u64,
}

/// Structure representing a stub for ImageInfo with fixed variables.
/// These fields are placeholders and may be changed as requirements are refined.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageInfo {
    pub var1: String,
    pub var2: String,
    pub var3: String,
}

/// Structure representing a service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Service {
    /// Unique identifier for the service.
    pub id: u64,
    /// Name of the service.
    pub name: String,
    /// Address of the service admin (creator).
    pub admin: Addr,
    /// Secret key for the service (placeholder, to be generated).
    pub secret_key: Option<String>,
    /// List of image information associated with the service (stub).
    pub image_infos: Vec<ImageInfo>,
}

/// Returns a mutable singleton for the global state.
pub fn global_state(storage: &mut dyn Storage) -> Singleton<GlobalState> {
    singleton(storage, GLOBAL_STATE_KEY)
}

/// Returns an immutable singleton for the global state.
pub fn global_state_read(storage: &dyn Storage) -> ReadonlySingleton<GlobalState> {
    singleton_read(storage, GLOBAL_STATE_KEY)
}

/// Returns a mutable singleton for the list of services.
pub fn services(storage: &mut dyn Storage) -> Singleton<Vec<Service>> {
    singleton(storage, SERVICES_KEY)
}

/// Returns an immutable singleton for the list of services.
pub fn services_read(storage: &dyn Storage) -> ReadonlySingleton<Vec<Service>> {
    singleton_read(storage, SERVICES_KEY)
}
