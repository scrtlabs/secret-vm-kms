use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, Event, attr, attr_plaintext};
use sha2::{Digest, Sha256};
use hex;
use core::mem;
#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use sha2::digest::Update;
use thiserror::Error;
use crate::crypto::{KeyPair, SIVEncryptable, SECRET_KEY_SIZE};
use crate::msg::{EnvSecretResponse, ExecuteMsg, ImageFilterHex, ImageFilterHexEntry, InstantiateMsg, ListImageResponse, MigrateMsg, MsgImageFilter, QueryMsg, SecretKeyResponse, ServiceResponse, DockerCredentialsResponse};
use crate::state::{global_state, global_state_read, services, services_read, GlobalState, Service, ImageFilter, image_secret_keys, image_secret_keys_read, env_secrets, EnvSecret, env_secrets_read, SERVICES_MAP, FilterEntry, OldService, DockerCredential, docker_credentials, docker_credentials_read, OLD_SERVICES_MAP};
use crate::import_helpers::{from_high_half, from_low_half};
use crate::memory::{build_region, Region};
use crate::msg::QueryMsg::ListImageFilters;

/// Declaration of tdx_quote_hdr_t and tdx_quote_t as provided.
/// DO NOT CHANGE THIS CODE.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tdx_quote_hdr_t {
    pub version: u16,
    pub key_type: u16,
    pub tee_type: u32,
    pub reserved: u32,
    pub qe_vendor_id: [u8;16],
    pub user_data: [u8;20],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct tdx_quote_t {
    pub header: tdx_quote_hdr_t,
    pub tcb_svn: [u8;16],
    pub mr_seam: [u8;48],
    pub mr_signer_seam: [u8;48],
    pub seam_attributes: [u8;8],
    pub td_attributes: [u8;8],
    pub xfam: [u8;8],
    pub mr_td: [u8;48],
    pub mr_config_id: [u8;48],
    pub mr_owner: [u8;48],
    pub mr_config: [u8;48],
    pub rtmr0: [u8;48],
    pub rtmr1: [u8;48],
    pub rtmr2: [u8;48],
    pub rtmr3: [u8;48],
    pub report_data: [u8;64],
}

#[derive(Error, Debug)]
pub enum SigningErrorC {
    #[error("Invalid private key format")]
    InvalidPrivateKeyFormat,
    #[error("Unknown error: {error_code}")]
    UnknownErr {
        error_code: u32,
        #[cfg(all(feature = "backtraces", error_generic_member_access))]
        backtrace: Backtrace,
    },
}

/// Declare the external function provided by the VM/chain.
///
/// This function is expected to take two pointers:
/// - `quote_ptr`: a pointer to a memory region containing the quote data.
/// - `collateral_ptr`: a pointer to a memory region containing the collateral data.
///
/// It returns a 64-bit integer where:
/// - The high half represents the error code.
/// - The low half represents the verification result.
extern "C" {
    fn dcap_quote_verify(quote_ptr: u32, collateral_ptr: u32) -> u64;
}

/// Verifies a DCAP quote using an external function.
///
/// This function packs the input slices `quote` and `collateral` into memory regions,
/// passes them to the external function, and decodes the result.
///
/// # Parameters
///
/// - `quote`: A byte slice containing the quote data.
/// - `collateral`: A byte slice containing the collateral data.
///
/// # Returns
///
/// - `Ok(u32)` with the verification result (from the low half of the returned value)
///   if the verification is successful (i.e., error code is 0).
/// - `Err(SigningError)` if an error occurs (i.e., non-zero error code).
// Production version: only compiled when not testing.
#[cfg(not(test))]
fn dcap_quote_verify_internal(quote: &[u8], collateral: &[u8]) -> Result<u32, SigningErrorC> {
    // Original implementation that uses build_region and an external FFI call.
    let quote_region = build_region(quote);
    let quote_ptr = &*quote_region as *const Region as u32;

    let collateral_region = build_region(collateral);
    let collateral_ptr = &*collateral_region as *const Region as u32;

    let result = unsafe { dcap_quote_verify(quote_ptr, collateral_ptr) };
    let error_code = from_high_half(result);
    let verify_result = from_low_half(result);

    match error_code {
        0 => Ok(verify_result),
        error_code => Err(SigningErrorC::UnknownErr { error_code }),
    }
}

// Test version: only compiled when testing.
#[cfg(test)]
fn dcap_quote_verify_internal(_quote: &[u8], _collateral: &[u8]) -> Result<u32, SigningErrorC> {
    // Simply return Ok(0) in tests.
    Ok(0)
}

fn parse_tdx_attestation(quote: &[u8], collateral: &[u8]) -> Option<tdx_quote_t> {
    match dcap_quote_verify_internal(quote, collateral) {
        Ok(_qv_result) => {},
        Err(_) => {
            return None;
        }
    }
    if quote.len() < mem::size_of::<tdx_quote_t>() {
        // "too small"
        return None;
    }
    let my_p_quote = quote.as_ptr() as *const tdx_quote_t;
    let tdx_quote = unsafe { *my_p_quote };
    if (tdx_quote.header.version != 4) || (tdx_quote.header.tee_type != 0x81) {
        // not a TDX quote
        None
    } else {
        Some(tdx_quote)
    }
}

#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => {
            // Step 1: Read all old records into memory to avoid borrow conflicts
            let mut buffer: Vec<(String, OldService)> = Vec::new();
            for item in OLD_SERVICES_MAP.iter(deps.storage)? {
                let (k, old) = item?;
                buffer.push((k, old));
            }

            // Step 2: Insert into the new map and remove from the old map
            let mut moved = 0u64;
            for (k, old) in buffer.into_iter() {
                let new = Service {
                    id: old.id.clone(),
                    name: old.name.clone(),
                    admin: old.admin.clone(),
                    filters: old.filters.clone(),
                    secret_key: old.secret_key.clone(),
                    secrets_plaintext: None, // new field remains empty after migration
                };

                // Insert the converted service into the new map
                SERVICES_MAP.insert(deps.storage, &k, &new)?;

                // Remove the old entry to clean up storage
                OLD_SERVICES_MAP.remove(deps.storage, &k)?;

                moved += 1;
            }

            Ok(Response::new()
                .add_attribute("action", "migrate_services_old_to_new")
                .add_attribute("moved", moved.to_string()))
        }
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

/// Instantiate the contract. Initializes global state and an empty services list.
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    let gs = GlobalState {
        service_count: 0,
        admin: info.sender.clone(), // set the global admin to the sender
    };
    global_state(deps.storage).save(&gs)?;
    let env_list: Vec<EnvSecret> = Vec::new();
    env_secrets(deps.storage).save(&env_list)?;
    let docker_credentials_list: Vec<DockerCredential> = Vec::new();
    docker_credentials(deps.storage).save(&docker_credentials_list)?;

    Ok(Response::default())
}

/// Execute entry point for handling ExecuteMsg.
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::CreateService { service_id, name } =>
            try_create_service(deps,env, info, service_id, name),
        ExecuteMsg::AddImageToService { service_id, image_filter, description } =>
            try_add_filter(deps, info, service_id, image_filter, description),
        ExecuteMsg::RemoveImageFromService { service_id, image_filter } =>
            try_remove_filter(deps, info, service_id, image_filter),
        ExecuteMsg::AddSecretKeyByImage { image_filter } => {
            try_add_secret_key_by_image(deps, env, info, image_filter)
        }
        // NEW: New operation to add or update an env secret by image.
        ExecuteMsg::AddEnvByImage { image_filter, secrets_plaintext } => {
            try_add_env_by_image(deps, env, info, image_filter, secrets_plaintext)
        }
        ExecuteMsg::AddDockerCredentialsByImage { image_filter, username, password_plaintext } => {
            try_add_docker_credentials_by_image(deps, env, info, image_filter, username, password_plaintext)
        }
        ExecuteMsg::AddEnvByService { service_id, secrets_plaintext } =>
            try_add_env_by_service(deps, env, info, service_id, secrets_plaintext),
    }
}

/// handler for adding service-level secret
pub fn try_add_env_by_service(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    service_id: String,
    secrets_plaintext: String,
) -> StdResult<Response> {
    // Only admin may add
    let mut svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    let gs = global_state_read(deps.storage).load()?;
    if info.sender.to_string() != svc.admin {
        return Err(StdError::generic_err("Only the service admin can add service env secret"));
    }
    // store or update secret
    svc.secrets_plaintext = Some(secrets_plaintext.clone());
    SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;
    Ok(Response::new()
        .add_attribute("action", "add_env_by_service")
        .add_attribute("service_id", service_id)
        .add_attribute("updated", "true"))
}

pub fn try_add_docker_credentials_by_image(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    image_filter: MsgImageFilter,
    username: String,
    password_plaintext: String,
) -> StdResult<Response> {
    // Ensure the sender is the global admin.
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err(
            "Only the admin can add docker credentials",
        ));
    }

    // Extract the VM uid (required)
    let vm_uid = image_filter.vm_uid
        .ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    // Check that the required fields are provided.
    if image_filter.mr_td.is_none()
        || image_filter.rtmr1.is_none()
        || image_filter.rtmr2.is_none()
        || image_filter.rtmr3.is_none()
    {
        return Err(StdError::generic_err(
            "Missing required fields in ImageFilter (mr_td, rtmr1, rtmr2, rtmr3 required)",
        ));
    }

    // Create a new DockerCredential structure from the provided image filter.
    let new_docker_credential = DockerCredential {
        mr_td: image_filter.mr_td.clone().unwrap(),
        rtmr1: image_filter.rtmr1.clone().unwrap(),
        rtmr2: image_filter.rtmr2.clone().unwrap(),
        rtmr3: image_filter.rtmr3.clone().unwrap(),
        vm_uid: Some(vm_uid),
        docker_username: username.clone(),
        docker_password_plaintext: password_plaintext.clone(),
    };

    let mut docker_credentials_list: Vec<DockerCredential> =
        docker_credentials(deps.storage).load().unwrap_or_else(|_| Vec::new());

    let mut updated = false;
    for cred in docker_credentials_list.iter_mut() {
        if cred.mr_td == new_docker_credential.mr_td
            && cred.rtmr1 == new_docker_credential.rtmr1
            && cred.rtmr2 == new_docker_credential.rtmr2
            && cred.rtmr3 == new_docker_credential.rtmr3
            && cred.vm_uid == new_docker_credential.vm_uid
        {
            // Update the credentials.
            cred.docker_username = username.clone();
            cred.docker_password_plaintext = password_plaintext.clone();
            updated = true;
            break;
        }
    }

    if !updated {
        docker_credentials_list.push(new_docker_credential);
    }

    docker_credentials(deps.storage).save(&docker_credentials_list)?;

    Ok(Response::new()
        .add_attribute("action", "add_docker_credentials_by_image")
        .add_attribute("updated", updated.to_string()))
}


/// NEW: Add or update an environment secret by image.
/// This function expects that the provided image filter includes non‑None values for
/// mr_td, rtmr1, rtmr2, and rtmr3, and it takes an additional secrets_plaintext string.
/// Only the admin can call this method.
pub fn try_add_env_by_image(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    image_filter: MsgImageFilter,
    secrets_plaintext: String,
) -> StdResult<Response> {
    // Ensure the sender is the global admin.
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err(
            "Only the admin can add env secrets",
        ));
    }

    // Extract the VM uid (required)
    let vm_uid = image_filter.vm_uid
        .ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    // Check that the required fields are provided.
    if image_filter.mr_td.is_none()
        || image_filter.rtmr1.is_none()
        || image_filter.rtmr2.is_none()
        || image_filter.rtmr3.is_none()
    {
        return Err(StdError::generic_err(
            "Missing required fields in ImageFilter (mr_td, rtmr1, rtmr2, rtmr3 required)",
        ));
    }
    // Create a new EnvSecret structure from the provided image filter.
    let new_env_secret = EnvSecret {
        mr_td: image_filter.mr_td.clone().unwrap(),
        rtmr1: image_filter.rtmr1.clone().unwrap(),
        rtmr2: image_filter.rtmr2.clone().unwrap(),
        rtmr3: image_filter.rtmr3.clone().unwrap(),
        vm_uid: Some(vm_uid),
        secrets_plaintext: secrets_plaintext.clone(),
    };

    // Load the current vector of environment secrets; if not found, initialize an empty vector.
    let mut env_secrets_list: Vec<EnvSecret> =
        env_secrets(deps.storage).load().unwrap_or_else(|_| Vec::new());

    // Look for an existing secret with matching fields.
    let mut updated = false;
    for secret in env_secrets_list.iter_mut() {
        if secret.mr_td == new_env_secret.mr_td
            && secret.rtmr1 == new_env_secret.rtmr1
            && secret.rtmr2 == new_env_secret.rtmr2
            && secret.rtmr3 == new_env_secret.rtmr3
            && secret.vm_uid == new_env_secret.vm_uid
        {
            // Update the plaintext.
            secret.secrets_plaintext = secrets_plaintext.clone();
            updated = true;
            break;
        }
    }
    // If no matching secret was found, add the new secret.
    if !updated {
        env_secrets_list.push(new_env_secret);
    }
    // Save the updated env secrets list back to storage.
    env_secrets(deps.storage).save(&env_secrets_list)?;

    Ok(Response::new()
        .add_attribute("action", "add_env_by_image")
        .add_attribute("updated", updated.to_string()))
}

pub fn try_add_secret_key_by_image(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    image_filter: MsgImageFilter,
) -> StdResult<Response> {
    // Only admin may add
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the contract admin can add a secret key by image"));
    }


    // Pull out just the four required fields (error if any missing)
    let mr_td    = image_filter.mr_td
        .ok_or_else(|| StdError::generic_err("mr_td required"))?;
    let rtmr1    = image_filter.rtmr1
        .ok_or_else(|| StdError::generic_err("rtmr1 required"))?;
    let rtmr2    = image_filter.rtmr2
        .ok_or_else(|| StdError::generic_err("rtmr2 required"))?;
    let rtmr3    = image_filter.rtmr3
        .ok_or_else(|| StdError::generic_err("rtmr3 required"))?;

    // Serialize *only* those
    let mut ser = Vec::new();
    ser.extend(&mr_td);
    ser.extend(&rtmr1);
    ser.extend(&rtmr2);
    ser.extend(&rtmr3);

    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, &ser);
    let image_key = hasher.finalize().to_vec();

    let mut bucket = image_secret_keys(deps.storage);
    if bucket.load(&image_key).is_ok() {
        return Ok(Response::new()
            .add_attribute("action", "add_secret_key_by_image")
            .add_attribute("message", "Already exists"));
    }

    // Derive a new secret exactly as before...
    let mut key_hasher = Sha256::new();
    let mut random_bytes = env.block.random.iter().flat_map(|b| b.as_slice()).cloned().collect::<Vec<_>>();
    sha2::Digest::update(&mut key_hasher, &random_bytes);
    sha2::Digest::update(&mut key_hasher, &ser);
    let secret = key_hasher.finalize().to_vec();

    bucket.save(&image_key, &hex::encode(&secret))?;

    Ok(Response::new()
        .add_attribute("action", "add_secret_key_by_image")
        .add_attribute("message", "Secret key created"))
}

/// Create service: generate secret_key via SHA256(env.random + id)
fn try_create_service(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_id: String,
    name: String,
) -> StdResult<Response> {
    let state = global_state_read(deps.storage).load()?;
    if info.sender.to_string() != state.admin { return Err(StdError::generic_err("Only admin")); }
    // Check for existing service_id
    if SERVICES_MAP.contains(deps.storage, &service_id) {
        return Err(StdError::generic_err("Service ID exists"));
    }
    // compute secret_key
    let mut hasher = Sha256::new();
    let mut random_bytes = Vec::new();
    for bin in env.block.random.iter() {
        random_bytes.extend_from_slice(bin.as_slice());
    }
    sha2::Digest::update(&mut hasher, &random_bytes);
    sha2::Digest::update(&mut hasher, service_id.as_bytes());
    let secret_key = hasher.finalize().to_vec();
    let svc = Service { id: service_id.clone(), name: name.clone(), admin: state.admin.clone(), secret_key, filters: Vec::new(), secrets_plaintext: None, };
    SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;
    Ok(Response::new().add_attribute("action","create_service").add_attribute("service_id",service_id).add_attribute("name",name))
}

/// Add filter
fn try_add_filter(
    deps: DepsMut,
    info: MessageInfo,
    service_id: String,
    image_filter: MsgImageFilter,
    description: String,
) -> StdResult<Response> {
    // Fetch service or error
    let mut svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    // Only admin may add
    if info.sender.to_string() != svc.admin {
        return Err(StdError::generic_err("Only the service admin can add image filter"));
    }
    // Convert MsgImageFilter to state::ImageFilter
    let entry_filter = ImageFilter {
        mr_seam: image_filter.mr_seam.clone(),
        mr_signer_seam: image_filter.mr_signer_seam.clone(),
        mr_td: image_filter.mr_td.clone(),
        mr_config_id: image_filter.mr_config_id.clone(),
        mr_owner: image_filter.mr_owner.clone(),
        mr_config: image_filter.mr_config.clone(),
        rtmr0: image_filter.rtmr0.clone(),
        rtmr1: image_filter.rtmr1.clone(),
        rtmr2: image_filter.rtmr2.clone(),
        rtmr3: image_filter.rtmr3.clone(),
    };
    // Add new filter entry
    svc.filters.push(FilterEntry { filter: entry_filter.clone(), description: description.clone() });
    // Persist updated service
    SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;
    // Prepare a JSON string of the filter for the event
    let filter_str = serde_json::to_string(&entry_filter).unwrap_or_default();
    // Build the event, conditionally adding the description attr
    let mut ev = Event::new("add_image_to_service")
        .add_attribute_plaintext("service_id", service_id.clone())
        .add_attribute_plaintext("admin", info.sender.to_string())
        .add_attribute_plaintext("image", filter_str);

    if !description.is_empty() {
        ev = ev.add_attribute_plaintext("description", description.clone());
    }

    // Build the response, conditionally adding the top‐level attribute too
    let mut resp = Response::new()
        .add_attribute("action", "add_image_to_service")
        .add_attribute("service_id", service_id.clone());

    if !description.is_empty() {
        resp = resp.add_attribute("description", description.clone());
    }

    Ok(resp.add_event(ev))
}

/// Remove filter: exact match required, emit event like before
fn try_remove_filter(
    deps: DepsMut,
    info: MessageInfo,
    service_id: String,
    image_filter: MsgImageFilter,
) -> StdResult<Response> {
    // Fetch service or error
    let mut svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    // Only admin may remove
    if info.sender.to_string() != svc.admin {
        return Err(StdError::generic_err("Only admin"));
    }
    // Convert MsgImageFilter into state::ImageFilter for comparison
    let removal_filter = ImageFilter {
        mr_seam: image_filter.mr_seam.clone(),
        mr_signer_seam: image_filter.mr_signer_seam.clone(),
        mr_td: image_filter.mr_td.clone(),
        mr_config_id: image_filter.mr_config_id.clone(),
        mr_owner: image_filter.mr_owner.clone(),
        mr_config: image_filter.mr_config.clone(),
        rtmr0: image_filter.rtmr0.clone(),
        rtmr1: image_filter.rtmr1.clone(),
        rtmr2: image_filter.rtmr2.clone(),
        rtmr3: image_filter.rtmr3.clone(),
    };
    let original_len = svc.filters.len();
    svc.filters.retain(|entry| entry.filter != removal_filter);
    if svc.filters.len() == original_len {
        return Err(StdError::generic_err("Filter not found"));
    }
    // Persist
    SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;
    // Prepare JSON for event
    let filter_str = serde_json::to_string(&removal_filter).unwrap_or_default();
    Ok(Response::new()
        .add_attribute("action", "remove_image_from_service")
        .add_attribute("service_id", service_id.clone())
        .add_event(
            Event::new("remove_image_from_service")
                .add_attribute_plaintext("service_id", service_id.clone())
                .add_attribute_plaintext("admin", info.sender.to_string())
                .add_attribute_plaintext("filter", filter_str)
        )
    )
}

/// New helper function to encrypt the secret key using AES-SIV.
/// It accepts a secret key (as a Vec<u8>) and a public key (a 32‑byte array),
/// generates an ephemeral key pair, computes the shared secret via Diffie‑Hellman,
/// and returns the encrypted secret key as a hex‑encoded string.
fn encrypt_secret(
    service_secret_key: Vec<u8>,
    other_pub_key: [u8; 32],
    quote: &[u8],
    height: Vec<u8>,
) -> StdResult<SecretKeyResponse> {
    // Compute seed = SHA256(service_secret_key || quote || other_pub_key || quote)
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, quote);
    sha2::Digest::update(&mut hasher, &other_pub_key);
    sha2::Digest::update(&mut hasher, &service_secret_key);
    sha2::Digest::update(&mut hasher, &height);
    let seed_hash = hasher.finalize();
    let mut seed = [0u8; SECRET_KEY_SIZE];
    seed.copy_from_slice(&seed_hash[..]);

    // Create ephemeral key pair using the computed seed.
    let kp = KeyPair::new_with_seed(seed)
        .map_err(|_| StdError::generic_err("Failed to generate ephemeral key pair with seed"))?;

    // Compute shared secret using the provided other_pub_key.
    let shared_key = kp.diffie_hellman(&other_pub_key);
    let aes_key = crate::crypto::AESKey::new_from_slice(&shared_key);
    let encrypted = aes_key
        .encrypt_siv(&service_secret_key, None)
        .map_err(|_| StdError::generic_err("Encryption failed"))?;
    let encrypted_secret_key = hex::encode(encrypted);

    Ok(SecretKeyResponse {
        encrypted_secret_key,
        // Also return the ephemeral public key (hex‑encoded)
        encryption_pub_key: hex::encode(kp.get_pubkey()),
    })
}


fn encrypt_docker_credentials(
    username_plaintext: String,
    password_plaintext: String,
    other_pub_key: [u8; 32],
    quote: &[u8],
    height: Vec<u8>,
) -> StdResult<DockerCredentialsResponse> {
    // Compute seed = SHA256(quote || other_pub_key || height)
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, quote);
    sha2::Digest::update(&mut hasher, &other_pub_key);
    sha2::Digest::update(&mut hasher, &height);
    let seed_hash = hasher.finalize();
    let mut seed = [0u8; SECRET_KEY_SIZE];
    seed.copy_from_slice(&seed_hash[..]);

    // Create ephemeral key pair using the computed seed.
    let kp = KeyPair::new_with_seed(seed)
        .map_err(|_| StdError::generic_err("Failed to generate ephemeral key pair with seed"))?;

    // Compute shared secret using the provided other_pub_key.
    let shared_key = kp.diffie_hellman(&other_pub_key);
    let aes_key = crate::crypto::AESKey::new_from_slice(&shared_key);

    // Encrypt username
    let encrypted_username = aes_key
        .encrypt_siv(username_plaintext.as_bytes(), None)
        .map_err(|_| StdError::generic_err("Username encryption failed"))?;

    // Encrypt password
    let encrypted_password = aes_key
        .encrypt_siv(password_plaintext.as_bytes(), None)
        .map_err(|_| StdError::generic_err("Password encryption failed"))?;

    Ok(DockerCredentialsResponse {
        encrypted_username: hex::encode(encrypted_username),
        encrypted_password: hex::encode(encrypted_password),
        encryption_pub_key: hex::encode(kp.get_pubkey()),
    })
}


/// Handles obtaining the secret key for a service.
/// It receives two buffers (quote and collateral), parses the TDX attestation using the provided function,
/// then iterates over stored image filters. For each filter, for every field that is Some,
/// it compares with the corresponding field from the parsed quote. Both the lengths and values must match.
/// If at least one filter fully matches, then the secret key is "encrypted" (dummy encryption: concatenation with report_data)
/// and returned.
pub fn try_get_secret_key(
    deps: Deps,
    env: Env,
    service_id: String,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<SecretKeyResponse> {
    // Load service
    let svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    // Verify and parse attestation
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Invalid attestation"))?;
    // Convert fields
    let t_mr_seam = tdx.mr_seam.to_vec();
    let t_mr_signer = tdx.mr_signer_seam.to_vec();
    let t_mr_td = tdx.mr_td.to_vec();
    let t_mr_config_id = tdx.mr_config_id.to_vec();
    let t_mr_owner = tdx.mr_owner.to_vec();
    let t_mr_config = tdx.mr_config.to_vec();
    let t_rtmr0 = tdx.rtmr0.to_vec();
    let t_rtmr1 = tdx.rtmr1.to_vec();
    let t_rtmr2 = tdx.rtmr2.to_vec();
    let t_rtmr3 = tdx.rtmr3.to_vec();
    // Match stored filters
    let mut found = false;
    for entry in svc.filters.iter() {
        let f = &entry.filter;
        if let Some(ref p) = f.mr_seam         { if p != &t_mr_seam       { continue; } }
        if let Some(ref p) = f.mr_signer_seam  { if p != &t_mr_signer     { continue; } }
        if let Some(ref p) = f.mr_td           { if p != &t_mr_td         { continue; } }
        if let Some(ref p) = f.mr_config_id    { if p != &t_mr_config_id  { continue; } }
        if let Some(ref p) = f.mr_owner        { if p != &t_mr_owner      { continue; } }
        if let Some(ref p) = f.mr_config       { if p != &t_mr_config     { continue; } }
        if let Some(ref p) = f.rtmr0           { if p != &t_rtmr0         { continue; } }
        if let Some(ref p) = f.rtmr1           { if p != &t_rtmr1         { continue; } }
        if let Some(ref p) = f.rtmr2           { if p != &t_rtmr2         { continue; } }
        if let Some(ref p) = f.rtmr3           { if p != &t_rtmr3         { continue; } }
        found = true;
        break;
    }
    if !found {
        return Err(StdError::generic_err("No matching image filter found"));
    }
    // Encrypt secret key
    let secret_key = svc.secret_key.clone();
    let other_pub: [u8;32] = tdx.report_data[0..32]
        .try_into()
        .map_err(|_| StdError::generic_err("Invalid report_data"))?;
    encrypt_secret(
        secret_key,
        other_pub,
        &quote,
        env.block.height.to_string().into_bytes(),
    )
}

pub fn try_get_secret_key_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<SecretKeyResponse> {
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation verification failed"))?;

    // Extract only the four slices
    let mr_td  = tdx.mr_td.to_vec();
    let r1     = tdx.rtmr1.to_vec();
    let r2     = tdx.rtmr2.to_vec();
    let r3     = tdx.rtmr3.to_vec();

    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, &mr_td);
    sha2::Digest::update(&mut hasher, &r1);
    sha2::Digest::update(&mut hasher, &r2);
    sha2::Digest::update(&mut hasher, &r3);
    let image_key = hasher.finalize().to_vec();

    let bucket = image_secret_keys_read(deps.storage);
    let secret_hex = bucket.load(&image_key)
        .map_err(|_| StdError::generic_err("Secret key for this image has not been created"))?;
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|_| StdError::generic_err("Stored secret is malformed"))?;

    // Now encrypt exactly as in `try_get_secret_key`
    let other_pub: [u8;32] = tdx.report_data[0..32].try_into()
        .map_err(|_| StdError::generic_err("Bad report_data"))?;
    let height_bytes = env.block.height.to_string().into_bytes();
    encrypt_secret(secret_bytes, other_pub, &quote, height_bytes)
}


/// Query entry point for handling QueryMsg.
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetService { id } => to_binary(&query_service(deps, id)?),
        QueryMsg::ListServices {} => to_binary(&query_services(deps)?),
        QueryMsg::GetSecretKey { service_id, quote, collateral } => {
            to_binary(&try_get_secret_key(deps, env.clone(), service_id, quote, collateral)?)
        }
        QueryMsg::GetSecretKeyByImage { quote, collateral } => {
            to_binary(&try_get_secret_key_by_image(deps, env, quote, collateral)?)
        }
        // NEW: Operation to retrieve env secret by image.
        QueryMsg::GetEnvByImage { quote, collateral } => {
            to_binary(&try_get_env_by_image(deps, env, quote, collateral)?)
        }
        QueryMsg::GetDockerCredentialsByImage { quote, collateral } => {
            to_binary(&try_get_docker_credentials_by_image(deps, env, quote, collateral)?)
        }
        /// Return filters (with descriptions) for a service
        ListImageFilters { service_id} =>  {
            to_binary(&query_image_filters(deps, service_id)?)
        }
        QueryMsg::GetEnvByService { service_id, quote, collateral } =>
            to_binary(&try_get_env_by_service(deps, env, service_id, quote, collateral)?),
    }
}

/// handler for retrieving service-level secret
pub fn try_get_env_by_service(
    deps: Deps,
    env: Env,
    service_id: String,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<EnvSecretResponse> {
    // verify attestation
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;
    // load service
    let svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    // ensure filter match
    let mut found = false;
    for entry in svc.filters.iter() {
        let f = &entry.filter;
        if let Some(ref p) = f.mr_seam         { if p != &tdx.mr_seam.to_vec()       { continue; } }
        if let Some(ref p) = f.mr_signer_seam  { if p != &tdx.mr_signer_seam.to_vec() { continue; } }
        if let Some(ref p) = f.mr_td           { if p != &tdx.mr_td.to_vec()         { continue; } }
        if let Some(ref p) = f.mr_config_id    { if p != &tdx.mr_config_id.to_vec()  { continue; } }
        if let Some(ref p) = f.mr_owner        { if p != &tdx.mr_owner.to_vec()      { continue; } }
        if let Some(ref p) = f.mr_config       { if p != &tdx.mr_config.to_vec()     { continue; } }
        if let Some(ref p) = f.rtmr0           { if p != &tdx.rtmr0.to_vec()         { continue; } }
        if let Some(ref p) = f.rtmr1           { if p != &tdx.rtmr1.to_vec()         { continue; } }
        if let Some(ref p) = f.rtmr2           { if p != &tdx.rtmr2.to_vec()         { continue; } }
        if let Some(ref p) = f.rtmr3           { if p != &tdx.rtmr3.to_vec()         { continue; } }
        found = true;
        break;
    }
    if !found {
        return Err(StdError::generic_err("No matching image filter found"));
    }
    // ensure secret exists
    let plaintext = svc.secrets_plaintext
        .clone()
        .ok_or_else(|| StdError::generic_err("Env secret for this service not set"))?;
    // encrypt
    let other_pub: [u8;32] = tdx.report_data[0..32]
        .try_into()
        .map_err(|_| StdError::generic_err("Bad report_data"))?;
    let height_bytes = env.block.height.to_string().into_bytes();
    let encrypted = encrypt_secret(plaintext.into_bytes(), other_pub, &quote, height_bytes)?;
    Ok(EnvSecretResponse {
        encrypted_secrets_plaintext: encrypted.encrypted_secret_key,
        encryption_pub_key: encrypted.encryption_pub_key,
    })
}

pub fn try_get_docker_credentials_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<DockerCredentialsResponse> {
    // Verify + parse
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;

    // Extract mr_td, rtmr1, rtmr2, rtmr3
    let mr_td = tdx.mr_td.to_vec();
    let r1    = tdx.rtmr1.to_vec();
    let r2    = tdx.rtmr2.to_vec();
    let r3    = tdx.rtmr3.to_vec();

    // Extract VM UID from report_data: next 16 bytes after the 32-byte pubkey, hex-encoded
    let vm_uid = tdx.report_data[32..48].to_vec();

    let docker_credentials_list = docker_credentials_read(deps.storage).load()?;
    let docker_credential = docker_credentials_list
        .into_iter()
        .find(|cred| {
            cred.mr_td == mr_td
                && cred.rtmr1 == r1
                && cred.rtmr2 == r2
                && cred.rtmr3 == r3
                && cred.vm_uid.as_ref().unwrap() == &vm_uid
        })
        .ok_or_else(|| StdError::generic_err("No docker credentials found for this image"))?;


    // Encrypt that plaintext
    let other_pub: [u8;32] = tdx.report_data[0..32].try_into()
        .map_err(|_| StdError::generic_err("Bad report_data"))?;
    let height_bytes = env.block.height.to_string().into_bytes();

    encrypt_docker_credentials(
        docker_credential.docker_username,
        docker_credential.docker_password_plaintext,
        other_pub,
        &quote,
        height_bytes,
    )
}

/// Query image filters, returning hex-encoded image fields
fn query_image_filters(deps: Deps, service_id: String) -> StdResult<ListImageResponse> {
    let svc = SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    let list = svc.filters.iter().map(|entry| {
        let f = &entry.filter;
        ImageFilterHexEntry {
            filter: ImageFilterHex {
                mr_seam: f.mr_seam.as_ref().map(|b| hex::encode(b)),
                mr_signer_seam: f.mr_signer_seam.as_ref().map(|b| hex::encode(b)),
                mr_td: f.mr_td.as_ref().map(|b| hex::encode(b)),
                mr_config_id: f.mr_config_id.as_ref().map(|b| hex::encode(b)),
                mr_owner: f.mr_owner.as_ref().map(|b| hex::encode(b)),
                mr_config: f.mr_config.as_ref().map(|b| hex::encode(b)),
                rtmr0: f.rtmr0.as_ref().map(|b| hex::encode(b)),
                rtmr1: f.rtmr1.as_ref().map(|b| hex::encode(b)),
                rtmr2: f.rtmr2.as_ref().map(|b| hex::encode(b)),
                rtmr3: f.rtmr3.as_ref().map(|b| hex::encode(b)),
            },
            description: entry.description.clone(),
        }
    }).collect();
    Ok(ListImageResponse { filters: list })
}

/// NEW: Retrieve the environment secret using an attestation.
/// This function verifies the provided quote and collateral, parses the attestation to extract
/// mr_td, rtmr1, rtmr2, and rtmr3, and then searches for an env secret with matching fields.
pub fn try_get_env_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<EnvSecretResponse> {
    // Verify + parse
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;

    // Extract mr_td, rtmr1, rtmr2, rtmr3
    let mr_td = tdx.mr_td.to_vec();
    let r1    = tdx.rtmr1.to_vec();
    let r2    = tdx.rtmr2.to_vec();
    let r3    = tdx.rtmr3.to_vec();

    // Extract VM UID from report_data: next 16 bytes after the 32-byte pubkey, hex-encoded
    let vm_uid = tdx.report_data[32..48].to_vec();

    // Prepare a default empty‐UID for legacy entries
    let default_vm_uid = vec![0u8; 16];

    // Load all env secrets and find the one that matches,
    // treating `None` as 16 zero bytes.
    let secret_plain = env_secrets_read(deps.storage)
        .load()?
        .into_iter()
        .find_map(|e| {
            // unwrap_or default to sixteen zero bytes
            let stored_uid = e.vm_uid.unwrap_or_else(|| default_vm_uid.clone());
            if e.mr_td == mr_td
                && e.rtmr1 == r1
                && e.rtmr2 == r2
                && e.rtmr3 == r3
                && stored_uid == vm_uid
            {
                Some(e.secrets_plaintext)
            } else {
                None
            }
        })
        .ok_or_else(|| StdError::generic_err("No env secret found"))?;

    // Encrypt that plaintext
    let other_pub: [u8;32] = tdx.report_data[0..32].try_into()
        .map_err(|_| StdError::generic_err("Bad report_data"))?;
    let height_bytes = env.block.height.to_string().into_bytes();
    let plaintext_bytes = secret_plain.as_bytes().to_vec();
    // we need a helper to encrypt arbitrary bytes:
    let encrypted = encrypt_secret(plaintext_bytes, other_pub, &quote, height_bytes)
        .map_err(|_| StdError::generic_err("Encryption failed"))?;
    Ok(EnvSecretResponse {
        encrypted_secrets_plaintext: encrypted.encrypted_secret_key,
        encryption_pub_key: encrypted.encryption_pub_key,
    })
}

/// Returns information about a service by its ID.
fn query_service(deps: Deps, id: String) -> StdResult<ServiceResponse> {
    let svc = SERVICES_MAP
        .get(deps.storage, &id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    Ok(ServiceResponse { id: svc.id, name: svc.name, admin: svc.admin.into_string() })
}

/// Returns a list of all services.
fn query_services(deps: Deps) -> StdResult<Vec<ServiceResponse>> {
    let mut resp: Vec<ServiceResponse> = Vec::new();
    for result in SERVICES_MAP.iter(deps.storage)? {
        let (_key, svc) = result?;
        resp.push(ServiceResponse {
            id: svc.id.clone(),
            name: svc.name.clone(),
            admin: svc.admin.clone().into_string(),
        });
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, StdError};

    // Override the external function dcap_quote_verify in tests so that it always returns 0,
    // meaning error_code is 0 and verification result is 0.
    #[cfg(test)]
    #[no_mangle]
    pub extern "C" fn dcap_quote_verify(_quote_ptr: u32, _collateral_ptr: u32) -> u64 {
        0
    }


    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {};
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();
        assert_eq!(0, res.messages.len());
        let res = query(deps.as_ref(), mock_env(), QueryMsg::ListServices {}).unwrap();
        let services_list: Vec<ServiceResponse> = from_binary(&res).unwrap();
        assert_eq!(services_list.len(), 0);
        let env_secrets_list: Vec<EnvSecret> = env_secrets_read(&deps.storage).load().unwrap();
        assert_eq!(env_secrets_list.len(), 0);
    }

    #[test]
    fn create_service() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Now include service_id in the CreateService call
        let exec_msg = ExecuteMsg::CreateService {
            service_id: "0".to_string(),
            name: "TestService".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), exec_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "create_service"));

        // Query by numeric ID 0
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetService { id: "0".to_string() },
        )
            .unwrap();
        let service: ServiceResponse = from_binary(&res).unwrap();
        assert_eq!(service.name, "TestService");
        assert_eq!(service.admin, "creator");
    }

    #[test]
    fn add_and_remove_image() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();
        let create_msg = ExecuteMsg::CreateService {service_id: "0".to_string(), name: "ServiceWithImage".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(vec![1,2,3,4,5]),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            vm_uid: None,
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), image_filter: image_filter.clone(), description: "TestImage".to_string() };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "add_image_to_service"));
        let remove_msg = ExecuteMsg::RemoveImageFromService { service_id: "0".to_string(), image_filter };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "remove_image_from_service"));
    }

    #[test]
    fn get_secret_key() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForKey".to_string(), service_id: "0".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();
        // Add an image filter that specifies mr_td must equal a specific vector of 48 bytes.
        let mut expected_mr_td = vec![0u8;48];
        expected_mr_td[..5].copy_from_slice(&[1,2,3,4,5]);
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(expected_mr_td.clone()),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            vm_uid: None,
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), image_filter, description: "TestImage".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        // Construct a dummy quote buffer of size_of::<tdx_quote_t>()
        let quote_len = mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];

        // set quote version to 4 and tee_type to 0x81
        quote[0] = 4;  // version low byte
        quote[1] = 0;  // version high byte

        // Set tee_type = 0x81 (129) as a u32 in little endian:
        quote[4] = 129; // 0x81
        quote[5] = 0;
        quote[6] = 0;
        quote[7] = 0;

        // Set mr_td field in the quote.
        // tdx_quote_t layout: header (2+2+4+4+16+20 = 48 bytes), then tcb_svn (16), mr_seam (48), mr_signer_seam (48), seam_attributes (8), td_attributes (8), xfam (8), then mr_td (48).
        // mr_td offset = 48 + 16 + 48 + 48 + 8 + 8 + 8 = 184.
        let mr_td_offset = 184;
        quote[mr_td_offset..mr_td_offset+48].copy_from_slice(&expected_mr_td);
        // Dummy collateral
        let collateral = vec![0u8; 10];
        let get_msg = QueryMsg::GetSecretKey { service_id: "0".to_string(), quote: quote.clone(), collateral: collateral.clone() };
        let res = query(deps.as_ref(), mock_env(), get_msg).unwrap();
        let secret_key: SecretKeyResponse = from_binary(&res).unwrap();
        assert!(!secret_key.encrypted_secret_key.is_empty());
        assert!(!secret_key.encryption_pub_key.is_empty());
    }

    #[test]
    fn get_secret_key_from_file() {
        // Read the quote and collateral data from files.
        let quote_path = Path::new("tests/quote.txt");
        let collateral_path = Path::new("tests/collateral.txt");
        let quote_hex = fs::read_to_string(quote_path)
            .expect("Failed to read quote.txt");
        let collateral_hex = fs::read_to_string(collateral_path)
            .expect("Failed to read collateral.txt");

        // Decode the hex strings into byte vectors (trim to remove any extra whitespace/newlines)
        let quote = hex::decode(quote_hex.trim())
            .expect("Failed to decode quote hex");
        let collateral = hex::decode(collateral_hex.trim())
            .expect("Failed to decode collateral hex");

        // Set up the contract with a service and an image filter that accepts any quote.
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create a new service.
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForFileKey".to_string(), service_id: "0".to_string()};
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();

        // Add an image filter that accepts any quote (all fields are None).
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: None,
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            vm_uid: None,
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), description: "TestImage".to_string(), image_filter };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();

        // Query the secret key using the quote and collateral read from file.
        let get_msg = QueryMsg::GetSecretKey { service_id: "0".to_string(), quote, collateral };
        let res = query(deps.as_ref(), mock_env(), get_msg).unwrap();
        let secret_key: SecretKeyResponse = from_binary(&res).unwrap();

        println!("secret_key: {:#?}", secret_key);
        println!("secret_key: {}", secret_key.encrypted_secret_key);

        // Since encryption uses ephemeral keys, we check that the result is non-empty and decodable.
        assert!(!secret_key.encrypted_secret_key.is_empty());
        let decoded = hex::decode(&secret_key.encrypted_secret_key)
            .expect("Failed to decode encrypted secret key");
        assert!(!decoded.is_empty());
    }

    #[test]
    fn unauthorized_add_image() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let other_info = mock_info("other", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();
        let create_msg = ExecuteMsg::CreateService { name: "UnauthorizedTest".to_string(), service_id: "0".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(vec![1,2,3]),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            vm_uid: None,
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), description: "TestImage".to_string(), image_filter };
        let res = execute(deps.as_mut(), mock_env(), other_info.clone(), add_msg);
        match res {
            Err(StdError::GenericErr { msg, .. }) => {
                assert_eq!(msg, "Only the service admin can add image filter");
            },
            _ => panic!("Expected unauthorized error"),
        }
    }

    #[test]
    fn list_image_filters_returns_hex() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        // Instantiate contract
        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // Create a service with ID "1"
        let svc_id = "1".to_string();
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::CreateService { service_id: svc_id.clone(), name: "Svc".to_string() },
        ).unwrap();

        // Add an image filter with known bytes and description
        let filter_bytes = vec![1u8, 2, 3];
        let msg_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(filter_bytes.clone()),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: None,
            rtmr2: None,
            rtmr3: None,
            vm_uid: None,
        };
        let desc = "test-desc".to_string();
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddImageToService {
                service_id: svc_id.clone(),
                image_filter: msg_filter.clone(),
                description: desc.clone(),
            },
        ).unwrap();

        // Query the list of filters
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ListImageFilters { service_id: svc_id.clone() },
        ).unwrap();
        let resp: ListImageResponse = from_binary(&res).unwrap();

        println!("Resp: {:#?}", resp);

        // Expect exactly one filter
        assert_eq!(resp.filters.len(), 1);
        // Check description
        assert_eq!(resp.filters[0].description, desc);
        // Check hex encoding of mr_td
        let hex_td = hex::encode(&filter_bytes);
        assert_eq!(resp.filters[0].filter.mr_td.as_ref().unwrap(), &hex_td);
    }

    #[test]
    fn add_and_get_secret_key_by_image() {
        use std::fs;
        use std::path::Path;
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
        use cosmwasm_std::{from_binary, StdError};
        use hex;

        // Initialize contract
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin_info.clone(), InstantiateMsg {}).unwrap();

        // Read quote & collateral from files
        let quote_hex = fs::read_to_string(Path::new("tests/quote.txt")).unwrap().trim().to_string();
        let collateral_hex = fs::read_to_string(Path::new("tests/collateral.txt")).unwrap().trim().to_string();
        let quote = hex::decode(&quote_hex).unwrap();
        let collateral = hex::decode(&collateral_hex).unwrap();

        // Parse to get report_data
        let tdx = parse_tdx_attestation(&quote, &collateral).expect("quote invalid");

        // Extract vm_uid from report_data bytes [32..48]
        let vm_uid = tdx.report_data[32..48].to_vec();


        let image_filter = MsgImageFilter {
            mr_seam: Some(tdx.mr_seam.to_vec()),
            mr_signer_seam: Some(tdx.mr_signer_seam.to_vec()),
            mr_td: Some(tdx.mr_td.to_vec()),
            mr_config_id: Some(tdx.mr_config_id.to_vec()),
            mr_owner: Some(tdx.mr_owner.to_vec()),
            mr_config: Some(tdx.mr_config.to_vec()),
            rtmr0: Some(tdx.rtmr0.to_vec()),
            rtmr1: Some(tdx.rtmr1.to_vec()),
            rtmr2: Some(tdx.rtmr2.to_vec()),
            rtmr3: Some(tdx.rtmr3.to_vec()),
            vm_uid: None,
        };

        // Store the secret key for this image
        execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            ExecuteMsg::AddSecretKeyByImage { image_filter: image_filter.clone() },
        ).unwrap();

        // Now query by image
        let query_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyByImage { quote: quote.clone(), collateral: collateral.clone() }
        ).unwrap();
        let resp: SecretKeyResponse = from_binary(&query_bin).unwrap();

        println!("resp: {:#?}", resp);

        // Should have both fields non-empty
        assert!(!resp.encrypted_secret_key.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn add_env_by_image_works() {
        // Set up dependencies and initialize the contract.
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create an image filter with the required fields (mr_td, rtmr1, rtmr2, rtmr3).
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(vec![10u8; 48]),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: Some(vec![20u8; 48]),
            rtmr2: Some(vec![30u8; 48]),
            rtmr3: Some(vec![40u8; 48]),
            vm_uid: Some("my-vm-id".into())
        };

        // Prepare the ExecuteMsg with AddEnvByImage.
        let exec_msg = ExecuteMsg::AddEnvByImage {
            image_filter: image_filter.clone(),
            secrets_plaintext: "env_secret_plaintext".to_string(),
        };

        // Execute the message.
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), exec_msg)
            .expect("AddEnvByImage execution failed");

        // Check that the response contains an attribute "action" with value "add_env_by_image".
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "add_env_by_image"));
    }

    #[test]
    fn get_secret_key_by_image_without_adding() {
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

        // Initialize dependencies and instantiate the contract.
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create a dummy quote of the proper length.
        let quote_len = mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];

        // Set header fields to satisfy parse_tdx_attestation:
        // The header layout is: version (u16), key_type (u16), tee_type (u32), reserved (u32), qe_vendor_id ([u8;16]), user_data ([u8;20]).
        // We'll set version = 4 and tee_type = 0x81.
        // Assume little-endian encoding.
        quote[0] = 4;  // version low byte
        quote[1] = 0;  // version high byte

        // key_type can remain 0.
        // Set tee_type = 0x81 (129) as a u32 in little endian:
        quote[4] = 129; // 0x81
        quote[5] = 0;
        quote[6] = 0;
        quote[7] = 0;

        // (Other header fields remain zero; that is acceptable for this dummy test.)

        // Now, set the report_data field (the last 64 bytes of the quote)
        // so that the first 32 bytes are nonzero (this will be used as the "other" public key).
        let report_data_offset = quote_len - 64;
        for i in report_data_offset..(report_data_offset + 32) {
            quote[i] = 1; // dummy public key (all ones)
        }

        // Create a dummy collateral.
        let collateral = vec![0u8; 10];

        // Now call try_get_secret_key_by_image. Since we have not added a secret key for this image,
        // we expect an error.
        let res = try_get_secret_key_by_image(deps.as_ref(), mock_env(), quote, collateral);
        println!("Result: {:?}", res);

        match res {
            Err(e) => {
                // Check that the error message matches our expectation.
                assert_eq!(
                    e.to_string(),
                    "Generic error: Secret key for this image has not been created"
                );
            }
            Ok(_) => panic!("Expected error since no secret key was added for this image"),
        }
    }

    #[test]
    fn get_env_by_image_returns_secret() {
        const TEST_VM_UID_HEX: &str = "00112233445566778899aabbccddeeff";
        let vm_uid_bytes = hex::decode(TEST_VM_UID_HEX).unwrap();

        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin_info.clone(), InstantiateMsg {}).unwrap();

        // Add env secret
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(vec![10u8; 48]),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: Some(vec![20u8; 48]),
            rtmr2: Some(vec![30u8; 48]),
            rtmr3: Some(vec![40u8; 48]),
            vm_uid: Some(vm_uid_bytes.clone()),
        };
        execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            ExecuteMsg::AddEnvByImage {
                image_filter: image_filter.clone(),
                secrets_plaintext: "env_secret_plaintext".to_string(),
            },
        ).unwrap();

        // Build dummy quote
        let quote_len = mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];
        quote[0] = 4; quote[1] = 0;
        quote[4] = 129; quote[5] = 0; quote[6] = 0; quote[7] = 0;

        let mr_td_offset = 184;
        quote[mr_td_offset..mr_td_offset + 48].copy_from_slice(&[10u8; 48]);
        let r1_off = 424;
        quote[r1_off..r1_off + 48].copy_from_slice(&[20u8; 48]);
        let r2_off = 472;
        quote[r2_off..r2_off + 48].copy_from_slice(&[30u8; 48]);
        let r3_off = 520;
        quote[r3_off..r3_off + 48].copy_from_slice(&[40u8; 48]);

        // report_data:
        let rd_off = quote_len - 64;
        // 32-byte pubkey stub:
        for i in rd_off..(rd_off + 32) { quote[i] = 1; }
        // 16-byte vm_uid
        quote[rd_off + 32..rd_off + 48].copy_from_slice(&vm_uid_bytes);

        let collateral = vec![0u8; 10];
        let res_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage { quote, collateral }
        ).unwrap();
        let resp: EnvSecretResponse = from_binary(&res_bin).unwrap();

        assert!(!resp.encrypted_secrets_plaintext.is_empty());
        assert!(hex::decode(&resp.encrypted_secrets_plaintext).is_ok());
        assert!(!resp.encryption_pub_key.is_empty());
        assert!(hex::decode(&resp.encryption_pub_key).is_ok());
    }

    #[test]
    fn get_env_by_image_from_file_returns_secret() {
        use std::fs;
        use std::path::Path;
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
        use cosmwasm_std::{from_binary, StdError};
        use hex;

        // --- Setup contract and admin ---
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin_info.clone(), InstantiateMsg {})
            .expect("instantiate should succeed");

        // --- Step 1. Read quote & collateral from files ---
        let quote_hex = fs::read_to_string(Path::new("tests/quote.txt"))
            .expect("reading quote.txt")
            .trim()
            .to_string();
        let collateral_hex = fs::read_to_string(Path::new("tests/collateral.txt"))
            .expect("reading collateral.txt")
            .trim()
            .to_string();

        let quote = hex::decode(&quote_hex).expect("decode quote hex");
        let collateral = hex::decode(&collateral_hex).expect("decode collateral hex");

        // --- Step 2. Parse the TDX attestation ---
        let tdx = parse_tdx_attestation(&quote, &collateral)
            .expect("attestation should parse");

        // --- Step 3. Extract the VM UID from report_data[32..48] ---
        let vm_uid = tdx.report_data[32..48].to_vec();

        // --- Step 4. Add the env secret, using the real fields from the quote ---
        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(tdx.mr_td.to_vec()),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: Some(tdx.rtmr1.to_vec()),
            rtmr2: Some(tdx.rtmr2.to_vec()),
            rtmr3: Some(tdx.rtmr3.to_vec()),
            vm_uid: Some(vm_uid),
        };
        execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            ExecuteMsg::AddEnvByImage {
                image_filter: image_filter.clone(),
                secrets_plaintext: "env_secret_plaintext".to_string(),
            },
        )
            .expect("AddEnvByImage must succeed");

        // --- Step 5. Query GetEnvByImage and verify ---
        let res_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage { quote: quote.clone(), collateral: collateral.clone() },
        )
            .expect("query GetEnvByImage");
        let resp: EnvSecretResponse = from_binary(&res_bin).unwrap();

        println!("resp: {:#?}", resp);

        // both fields should be non‐empty and valid hex
        assert!(!resp.encrypted_secrets_plaintext.is_empty(), "encrypted_secrets_plaintext must not be empty");
        assert!(hex::decode(&resp.encrypted_secrets_plaintext).is_ok(), "must be valid hex");
        assert!(!resp.encryption_pub_key.is_empty(), "encryption_pub_key must not be empty");
        assert!(hex::decode(&resp.encryption_pub_key).is_ok(), "must be valid hex");
    }

    #[test]
    fn test_encrypt_secret_function() {
        // Use a dummy secret key.
        let secret_key = b"dummy_secret_key".to_vec();
        // Use a fixed public key (32 bytes).
        let public_key: [u8; 32] = [1; 32];

        // Call the encryption function.
        let encrypted = encrypt_secret(secret_key, public_key, "test".to_string().as_bytes(), "52".to_string().into_bytes()).unwrap();

        println!("encrypted: {:?}", encrypted);

        // Ensure that the encrypted string is not empty.
        assert!(!encrypted.encrypted_secret_key.is_empty());

        // Attempt to decode the hex string to verify the correct format.
        let decoded = hex::decode(&encrypted.encrypted_secret_key).unwrap();

        println!("decoded: {:?}", decoded);
        assert!(!decoded.is_empty());
    }

    #[test]
    fn prepare_secretcli_get_secret_key_command() {
        use std::fs;
        use std::path::Path;
        use serde_json;

        // Define paths for the quote and collateral files.
        let quote_path = Path::new("tests/quote.txt");
        let collateral_path = Path::new("tests/collateral.txt");

        // Read the hex strings from the files.
        let quote_hex = fs::read_to_string(quote_path)
            .expect("Failed to read quote.txt")
            .trim()
            .to_string();
        let collateral_hex = fs::read_to_string(collateral_path)
            .expect("Failed to read collateral.txt")
            .trim()
            .to_string();

        // Decode the hex strings into Vec<u8>.
        let quote_vec = hex::decode(&quote_hex).expect("Failed to decode quote hex");
        let collateral_vec = hex::decode(&collateral_hex).expect("Failed to decode collateral hex");

        // Serialize the Vec<u8> into JSON arrays.
        let quote_json = serde_json::to_string(&quote_vec).unwrap();
        let collateral_json = serde_json::to_string(&collateral_vec).unwrap();

        // Define contract address and service id.
        let contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu";
        let service_id = "0";

        // Build the query JSON string with escaped quotes.
        // Note: The JSON arrays for quote and collateral are inserted directly (without extra quotes).
        let query_json = format!(
            "{{\\\"get_secret_key\\\":{{\\\"service_id\\\":{},\\\"quote\\\":{},\\\"collateral\\\":{}}}}}",
            service_id, quote_json, collateral_json
        );

        // Build the SecretCLI command string without the --query flag.
        let command = format!(
            "secretcli q compute query {} {}",
            contract_address, query_json
        );

        println!("SecretCLI command: {}", command);
    }

    #[test]
    fn dump_report_data_from_quote_file() {
        // Read the quote and collateral hex strings from disk
        let quote_path = Path::new("tests/quote.txt");
        let collateral_path = Path::new("tests/collateral.txt");
        let quote_hex = fs::read_to_string(quote_path)
            .expect("Failed to read tests/quote.txt");
        let collateral_hex = fs::read_to_string(collateral_path)
            .expect("Failed to read tests/collateral.txt");

        // Decode the hex into raw bytes
        let quote = hex::decode(quote_hex.trim())
            .expect("Failed to decode quote hex");
        let collateral = hex::decode(collateral_hex.trim())
            .expect("Failed to decode collateral hex");

        // Parse the TDX attestation
        let tdx = parse_tdx_attestation(&quote, &collateral)
            .expect("Quote verification or parsing failed");

        // Extract report_data and encode it as hex
        let report_data = &tdx.report_data;
        let report_data_hex = hex::encode(report_data);

        // Print the hex-encoded report_data for inspection
        println!("report_data: {}", report_data_hex);

        // Assert that report_data is non-empty
        assert!(!report_data_hex.is_empty(), "report_data should not be empty");
    }

    #[test]
    fn add_and_get_docker_credentials_by_image() {
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
        use cosmwasm_std::{from_binary, StdError};
        use hex;

        // Initialize contract
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin_info.clone(), InstantiateMsg {}).unwrap();

        // Read quote & collateral from files
        let quote_hex = fs::read_to_string(Path::new("tests/quote.txt")).unwrap().trim().to_string();
        let collateral_hex = fs::read_to_string(Path::new("tests/collateral.txt")).unwrap().trim().to_string();
        let quote = hex::decode(&quote_hex).unwrap();
        let collateral = hex::decode(&collateral_hex).unwrap();

        // Parse to get report_data
        let tdx = parse_tdx_attestation(&quote, &collateral).expect("quote invalid");

        // Extract vm_uid from report_data bytes [32..48]
        let vm_uid = tdx.report_data[32..48].to_vec();

        let image_filter = MsgImageFilter {
            mr_seam: None,
            mr_signer_seam: None,
            mr_td: Some(tdx.mr_td.to_vec()),
            mr_config_id: None,
            mr_owner: None,
            mr_config: None,
            rtmr0: None,
            rtmr1: Some(tdx.rtmr1.to_vec()),
            rtmr2: Some(tdx.rtmr2.to_vec()),
            rtmr3: Some(tdx.rtmr3.to_vec()),
            vm_uid: Some(vm_uid),
        };

        // Add the docker credentials
        execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            ExecuteMsg::AddDockerCredentialsByImage {
                image_filter: image_filter.clone(),
                username: "testuser".to_string(),
                password_plaintext: "testpassword".to_string(),
            },
        ).unwrap();

        // Now query by image
        let query_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetDockerCredentialsByImage { quote: quote.clone(), collateral: collateral.clone() }
        ).unwrap();

        let resp: DockerCredentialsResponse = from_binary(&query_bin).unwrap();

        // Should have all fields non-empty
        assert!(!resp.encrypted_username.is_empty());
        assert!(!resp.encrypted_password.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn add_env_by_service_works() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();
        // Create service
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string() }
        ).unwrap();
        // Add env secret
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddEnvByService { service_id: "svc1".to_string(), secrets_plaintext: "secret!".to_string() }
        ).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "action" && a.value == "add_env_by_service"));
    }

    #[test]
    fn get_env_by_service_fails_without_secret() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string() }
        ).unwrap();


        // IMPORTANT: add at least one image filter so filter matching passes
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc1".to_string(),
                image_filter: MsgImageFilter { mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None, mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None, vm_uid: None },
                description: "".to_string(),
            }
        ).unwrap();

        // Build dummy quote
        let quote_len = std::mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len]; quote[0]=4; quote[4]=129;
        let collateral = vec![0u8;10];
        let err = try_get_env_by_service(
            deps.as_ref(), mock_env(), "svc1".to_string(), quote, collateral
        );
        match err {
            Err(StdError::GenericErr { msg, .. }) => assert_eq!(msg, "Env secret for this service not set"),
            _ => panic!("Expected GenericErr"),
        }
    }

    #[test]
    fn add_and_get_env_by_service_success() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();
        // Create and add filter
        execute(
            deps.as_mut(), mock_env(), admin.clone(),
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string() }
        ).unwrap();
        // reuse existing AddImageToService test setup to ensure a matching filter exists
        // ... (add a filter requiring no specific fields to match)
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc1".to_string(),
                image_filter: MsgImageFilter { mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None, mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None, vm_uid: None },
                description: "".to_string(),
            }
        ).unwrap();
        // Add service env secret
        execute(
            deps.as_mut(), mock_env(), admin.clone(),
            ExecuteMsg::AddEnvByService { service_id: "svc1".to_string(), secrets_plaintext: "supersecret".to_string() }
        ).unwrap();
        // Query it via attestation
        let quote_len = std::mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len]; quote[0]=4; quote[4]=129;
        let collateral = vec![0u8;10];
        let bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByService { service_id: "svc1".to_string(), quote, collateral }
        ).unwrap();
        let resp: EnvSecretResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secrets_plaintext.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }
}
