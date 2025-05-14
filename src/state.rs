use cosmwasm_std::{Addr, StdResult, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

static GLOBAL_STATE_KEY: &[u8] = b"global_state";
static SERVICES_KEY: &[u8] = b"services";
// NEW: Key for storing env secrets.
pub static ENV_SECRETS_KEY: &[u8] = b"env_secrets";

// NEW: import bucket helpers
use cosmwasm_storage::{bucket, bucket_read, Bucket, ReadonlyBucket};

pub const IMAGE_SECRET_KEYS_KEY: &[u8] = b"image_secret_keys";

/// Returns a mutable bucket mapping from image hash (Vec<u8>) to a secret key (String)
pub fn image_secret_keys(storage: &mut dyn cosmwasm_std::Storage) -> Bucket<String> {
    bucket(storage, IMAGE_SECRET_KEYS_KEY)
}

/// Returns an immutable bucket for image secret keys.
pub fn image_secret_keys_read(storage: &dyn cosmwasm_std::Storage) -> ReadonlyBucket<String> {
    bucket_read(storage, IMAGE_SECRET_KEYS_KEY)
}

/// NEW: Returns a mutable singleton for the list of environment secrets.
pub fn env_secrets(storage: &mut dyn Storage) -> Singleton<Vec<EnvSecret>> {
    singleton(storage, ENV_SECRETS_KEY)
}

/// NEW: Returns an immutable singleton for the list of environment secrets.
pub fn env_secrets_read(storage: &dyn Storage) -> ReadonlySingleton<Vec<EnvSecret>> {
    singleton_read(storage, ENV_SECRETS_KEY)
}

/// Global state of the contract which tracks the number of created services.
/// This counter is also used to generate new service IDs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GlobalState {
    pub service_count: u64,
    pub admin: Addr, // new field: the contract admin (set at instantiation)
}

/// Structure representing an image filter (attestation parameters) for a service.
/// Fields correspond to those in `tdx_quote_t` (except header) and are wrapped in Option.
/// Теперь поля имеют тип Option<Vec<u8>> для гибкости сравнения.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageFilter {
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

/// Structure representing a service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Service {
    /// Unique identifier for the service.
    pub id: u64,
    /// Name of the service.
    pub name: String,
    /// Address of the service admin (creator).
    pub admin: Addr,
    /// Secret key for the service.
    pub secret_key: Vec<u8>,
    /// List of image filters (permitted attestation parameters) associated with the service.
    pub image_filters: Vec<ImageFilter>,
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

/// NEW: Structure representing an environment secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct EnvSecret {
    pub mr_td: Vec<u8>,
    pub rtmr1: Vec<u8>,
    pub rtmr2: Vec<u8>,
    pub rtmr3: Vec<u8>,
    pub vm_uid: Option<Vec<u8>>,
    pub secrets_plaintext: String,
}