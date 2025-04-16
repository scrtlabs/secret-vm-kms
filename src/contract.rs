use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, Event, attr, attr_plaintext};
use sha2::{Digest, Sha256};
use hex;
use core::mem;
#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use sha2::digest::Update;
use thiserror::Error;
use crate::crypto::{KeyPair, SIVEncryptable, SECRET_KEY_SIZE};
use crate::msg::{EnvSecretResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, MsgImageFilter, QueryMsg, SecretKeyResponse, ServiceResponse};
use crate::state::{global_state, global_state_read, services, services_read, GlobalState, Service, ImageFilter, image_secret_keys, image_secret_keys_read, env_secrets, EnvSecret, env_secrets_read};
use crate::import_helpers::{from_high_half, from_low_half};
use crate::memory::{build_region, Region};

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
            let admin = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();
            // Load the current global state, update the admin, and save it.
            let mut gs = global_state(deps.storage).load()?;
            gs.admin = deps.api.addr_validate(&admin)?;
            global_state(deps.storage).save(&gs)?;
            Ok(Response::new()
                .add_attribute("action", "migrate")
                .add_attribute("admin", gs.admin.to_string()))
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
    let svc_list: Vec<Service> = Vec::new();
    services(deps.storage).save(&svc_list)?;
    // Also initialize the bucket for image secret keys (nothing to store initially)
    // And initialize the environment secrets as an empty vector.
    let env_list: Vec<EnvSecret> = Vec::new();
    env_secrets(deps.storage).save(&env_list)?;
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
        ExecuteMsg::CreateService { name } => try_create_service(deps, env, info, name),
        ExecuteMsg::AddImageToService { service_id, image_filter } => {
            try_add_image(deps, info, service_id, image_filter)
        }
        ExecuteMsg::RemoveImageFromService { service_id, image_filter } => {
            try_remove_image(deps, info, service_id, image_filter)
        }
        ExecuteMsg::AddSecretKeyByImage { image_filter } => {
            try_add_secret_key_by_image(deps, env, info, image_filter)
        }
        // NEW: New operation to add or update an env secret by image.
        ExecuteMsg::AddEnvByImage { image_filter, secrets_plaintext } => {
            try_add_env_by_image(deps, env, info, image_filter, secrets_plaintext)
        }
    }
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
    // Ensure the sender is the global admin.
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the contract admin can add a secret key by image"));
    }
    // Serialize the image filter (as provided) and compute its hash.
    let image_filter_serialized = serde_json::to_vec(&image_filter)
        .map_err(|_| StdError::generic_err("Failed to serialize image filter"))?;
    let mut hasher = Sha256::new();
    // Use the image filter serialization (you could also include extra image field data if needed)
    sha2::Digest::update(&mut hasher, &image_filter_serialized);
    let image_hash = hasher.finalize();
    let image_key = image_hash.to_vec();

    // Access the separate bucket for image secret keys.
    let mut bucket = image_secret_keys(deps.storage);
    if bucket.load(&image_key).is_ok() {
        return Ok(Response::new()
            .add_attribute("action", "add_secret_key_by_image")
            .add_attribute("message", "Secret key for this image already exists"));
    }

    // Create a new secret key for the image using env.block.random (same as in service creation).
    let mut key_hasher = Sha256::new();
    let mut random_bytes = Vec::new();
    // Use the block random to create a seed (just like in try_create_service)
    for bin in env.block.random.iter() {
        random_bytes.extend_from_slice(bin.as_slice());
    }
    // Incorporate the random bytes and image data (e.g., the serialized image filter) into the seed.
    sha2::Digest::update(&mut key_hasher, &random_bytes);
    sha2::Digest::update(&mut key_hasher, &image_filter_serialized);
    let new_secret = key_hasher.finalize().to_vec();

    // Store the new secret key (unencrypted, as a hex string) in the bucket.
    bucket.save(&image_key, &hex::encode(new_secret.clone()))?;

    Ok(Response::new()
        .add_attribute("action", "add_secret_key_by_image")
        .add_attribute("message", "Secret key created for the image"))
}

/// Handles creating a new service.
/// Generates secret_key as SHA256(env.block.random + service_id) in hex.
/// Handles creating a new service (unchanged aside from uniqueness check, if needed).
pub fn try_create_service(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    name: String,
) -> StdResult<Response> {
    let mut gs = global_state(deps.storage).load()?;
    let mut svc_list = services(deps.storage).load()?;

    // Enforce unique service names.
    if svc_list.iter().any(|s| s.name == name) {
        return Err(StdError::generic_err("Service name already exists"));
    }

    let service_id = gs.service_count;
    let mut hasher = Sha256::new();
    let mut random_bytes = Vec::new();
    for bin in env.block.random.iter() {
        random_bytes.extend_from_slice(bin.as_slice());
    }
    sha2::Digest::update(&mut hasher, &random_bytes);
    sha2::Digest::update(&mut hasher, &service_id.to_be_bytes());
    let secret_hash = hasher.finalize();
    let secret = secret_hash.to_vec();

    let new_service = Service {
        id: service_id,
        name: name.clone(),
        admin: info.sender.clone(),
        secret_key: secret,
        image_filters: Vec::new(),
    };

    svc_list.push(new_service);
    gs.service_count += 1;
    global_state(deps.storage).save(&gs)?;
    services(deps.storage).save(&svc_list)?;
    Ok(Response::new()
        .add_attribute("action", "create_service")
        .add_attribute("service_id", service_id.to_string())
        .add_attribute("name", name)
        .add_attribute("admin", info.sender.to_string()))
}

/// Handles adding an image filter to a service.
/// The filter contains fields (all Option<Vec<u8>>) corresponding to `tdx_quote_t` fields.
/// Only the service admin can add.
pub fn try_add_image(
    deps: DepsMut,
    info: MessageInfo,
    service_id: u64,
    image_filter: MsgImageFilter,
) -> StdResult<Response> {
    let mut svc_list = services(deps.storage).load()?;
    let filter_str = {
        let service = svc_list.iter_mut().find(|s| s.id == service_id)
            .ok_or_else(|| StdError::generic_err("Service not found"))?;
        if info.sender != service.admin {
            return Err(StdError::generic_err("Only the service admin can add image filter"));
        }
        service.image_filters.push(ImageFilter {
            mr_seam: image_filter.mr_seam,
            mr_signer_seam: image_filter.mr_signer_seam,
            mr_td: image_filter.mr_td,
            mr_config_id: image_filter.mr_config_id,
            mr_owner: image_filter.mr_owner,
            mr_config: image_filter.mr_config,
            rtmr0: image_filter.rtmr0,
            rtmr1: image_filter.rtmr1,
            rtmr2: image_filter.rtmr2,
            rtmr3: image_filter.rtmr3,
        });
        serde_json::to_string(&service.image_filters.last().unwrap()).unwrap_or_default()
    };
    services(deps.storage).save(&svc_list)?;
    Ok(Response::new()
        .add_attribute("action", "add_image_to_service")
        .add_attribute("service_id", service_id.to_string())
        .add_event(
            Event::new("add_image_to_service")
                .add_attribute_plaintext("service_id", service_id.to_string())
                .add_attribute_plaintext("admin", info.sender.to_string())
                .add_attribute_plaintext("Image", filter_str)
        ))
}

/// Handles removing an image filter from a service.
/// Exact match is required for removal.
pub fn try_remove_image(
    deps: DepsMut,
    info: MessageInfo,
    service_id: u64,
    image_filter: MsgImageFilter,
) -> StdResult<Response> {
    let mut svc_list = services(deps.storage).load()?;
    let service = svc_list.iter_mut().find(|s| s.id == service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    if info.sender != service.admin {
        return Err(StdError::generic_err("Only the service admin can remove image filter"));
    }
    let original_len = service.image_filters.len();
    service.image_filters.retain(|img| {
        !(img.mr_seam == image_filter.mr_seam &&
            img.mr_signer_seam == image_filter.mr_signer_seam &&
            img.mr_td == image_filter.mr_td &&
            img.mr_config_id == image_filter.mr_config_id &&
            img.mr_owner == image_filter.mr_owner &&
            img.mr_config == image_filter.mr_config &&
            img.rtmr0 == image_filter.rtmr0 &&
            img.rtmr1 == image_filter.rtmr1 &&
            img.rtmr2 == image_filter.rtmr2 &&
            img.rtmr3 == image_filter.rtmr3)
    });
    if service.image_filters.len() == original_len {
        return Err(StdError::generic_err("Image filter with given parameters not found"));
    }
    services(deps.storage).save(&svc_list)?;
    Ok(Response::new()
        .add_attribute("action", "remove_image_from_service")
        .add_attribute("service_id", service_id.to_string())
        .add_event(
            Event::new("remove_image_from_service")
                .add_attribute_plaintext("service_id", service_id.to_string())
                .add_attribute_plaintext("admin", info.sender.to_string())
                .add_attribute_plaintext("Image", serde_json::to_string(&image_filter).unwrap_or_default())
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

/// Handles obtaining the secret key for a service.
/// It receives two buffers (quote and collateral), parses the TDX attestation using the provided function,
/// then iterates over stored image filters. For each filter, for every field that is Some,
/// it compares with the corresponding field from the parsed quote. Both the lengths and values must match.
/// If at least one filter fully matches, then the secret key is "encrypted" (dummy encryption: concatenation with report_data)
/// and returned.
pub fn try_get_secret_key(
    deps: Deps,
    env: Env,
    service_id: u64,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<SecretKeyResponse> {
    let svc_list = services_read(deps.storage).load()?;
    let service = svc_list.into_iter().find(|s| s.id == service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    let tdx_quote = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation verification failed or quote invalid"))?;

    // println!("tdx_quote: {:#?}", tdx_quote);

    // Convert fixed arrays from tdx_quote to Vec<u8> for comparison.
    let tdx_mr_seam = tdx_quote.mr_seam.to_vec();
    let tdx_mr_signer_seam = tdx_quote.mr_signer_seam.to_vec();
    let tdx_mr_td = tdx_quote.mr_td.to_vec();
    let tdx_mr_config_id = tdx_quote.mr_config_id.to_vec();
    let tdx_mr_owner = tdx_quote.mr_owner.to_vec();
    let tdx_mr_config = tdx_quote.mr_config.to_vec();
    let tdx_rtmr0 = tdx_quote.rtmr0.to_vec();
    let tdx_rtmr1 = tdx_quote.rtmr1.to_vec();
    let tdx_rtmr2 = tdx_quote.rtmr2.to_vec();
    let tdx_rtmr3 = tdx_quote.rtmr3.to_vec();
    let tdx_report_data = tdx_quote.report_data.to_vec();

    let mut match_found = false;
    'outer: for filter in service.image_filters.iter() {
        if let Some(ref permitted) = filter.mr_seam {
            if permitted.len() != tdx_mr_seam.len() || permitted != &tdx_mr_seam {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.mr_signer_seam {
            if permitted.len() != tdx_mr_signer_seam.len() || permitted != &tdx_mr_signer_seam {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.mr_td {
            if permitted.len() != tdx_mr_td.len() || permitted != &tdx_mr_td {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.mr_config_id {
            if permitted.len() != tdx_mr_config_id.len() || permitted != &tdx_mr_config_id {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.mr_owner {
            if permitted.len() != tdx_mr_owner.len() || permitted != &tdx_mr_owner {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.mr_config {
            if permitted.len() != tdx_mr_config.len() || permitted != &tdx_mr_config {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.rtmr0 {
            if permitted.len() != tdx_rtmr0.len() || permitted != &tdx_rtmr0 {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.rtmr1 {
            if permitted.len() != tdx_rtmr1.len() || permitted != &tdx_rtmr1 {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.rtmr2 {
            if permitted.len() != tdx_rtmr2.len() || permitted != &tdx_rtmr2 {
                continue 'outer;
            }
        }
        if let Some(ref permitted) = filter.rtmr3 {
            if permitted.len() != tdx_rtmr3.len() || permitted != &tdx_rtmr3 {
                continue 'outer;
            }
        }
        // All specified fields in this filter match.
        match_found = true;
        break;
    }
    if !match_found {
        return Err(StdError::generic_err("Attestation parameters do not match any permitted image"));
    }
    let secret_key = service.secret_key;
    // Extract the first 32 bytes from report_data to serve as the "other" public key.
    let other_pub_key: [u8; 32] = tdx_quote.report_data[0..32]
        .try_into()
        .map_err(|_| StdError::generic_err("Failed to extract public key from report_data"))?;
    // Encrypt the service secret key using the new helper function.
    let encrypted_secret_key_response = encrypt_secret(secret_key, other_pub_key,quote.as_slice(),env.block.height.to_string().into_bytes())?;
    Ok(encrypted_secret_key_response)
}

pub fn try_get_secret_key_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<SecretKeyResponse> {
    // Parse the attestation.
    let tdx_quote = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation verification failed or quote invalid"))?;
    // Reconstruct a minimal image filter from tdx_quote fields.
    let image_filter = MsgImageFilter {
        mr_seam: Some(tdx_quote.mr_seam.to_vec()),
        mr_signer_seam: Some(tdx_quote.mr_signer_seam.to_vec()),
        mr_td: Some(tdx_quote.mr_td.to_vec()),
        mr_config_id: Some(tdx_quote.mr_config_id.to_vec()),
        mr_owner: Some(tdx_quote.mr_owner.to_vec()),
        mr_config: Some(tdx_quote.mr_config.to_vec()),
        rtmr0: Some(tdx_quote.rtmr0.to_vec()),
        rtmr1: Some(tdx_quote.rtmr1.to_vec()),
        rtmr2: Some(tdx_quote.rtmr2.to_vec()),
        rtmr3: Some(tdx_quote.rtmr3.to_vec()),
    };
    let image_filter_serialized = serde_json::to_vec(&image_filter)
        .map_err(|_| StdError::generic_err("Failed to serialize image filter"))?;
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, &image_filter_serialized);
    let image_hash = hasher.finalize();
    let image_key = image_hash.to_vec();

    let bucket = image_secret_keys_read(deps.storage);
    let stored_secret_hex = bucket
        .load(&image_key)
        .map_err(|_| StdError::generic_err("Secret key for this image has not been created"))?;
    // Convert stored secret key back to bytes.
    let stored_secret = hex::decode(stored_secret_hex)
        .map_err(|_| StdError::generic_err("Failed to decode stored secret key"))?;

    // Extract the "other" public key from report_data.
    let other_pub_key: [u8; 32] = tdx_quote.report_data[0..32]
        .try_into()
        .map_err(|_| StdError::generic_err("Failed to extract public key from report_data"))?;
    // Use env.block.height as height.
    let height_bytes = env.block.height.to_string().into_bytes();

    // Encrypt the stored secret key using the same encryption procedure.
    let response = encrypt_secret(stored_secret, other_pub_key, &quote, height_bytes)?;
    Ok(response)
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
    }
}

/// NEW: Retrieve the environment secret using an attestation.
/// This function verifies the provided quote and collateral, parses the attestation to extract
/// mr_td, rtmr1, rtmr2, and rtmr3, and then searches for an env secret with matching fields.
/// If found, it returns the associated plaintext in a response.
pub fn try_get_env_by_image(
    deps: Deps,
    _env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<EnvSecretResponse> {
    // Verify the attestation and parse the quote.
    let tdx_quote = parse_tdx_attestation(&quote, &collateral).ok_or_else(|| {
        StdError::generic_err("Attestation verification failed or quote invalid")
    })?;
    // Extract the relevant fields from the parsed tdx_quote.
    let tdx_mr_td = tdx_quote.mr_td.to_vec();
    let tdx_rtmr1 = tdx_quote.rtmr1.to_vec();
    let tdx_rtmr2 = tdx_quote.rtmr2.to_vec();
    let tdx_rtmr3 = tdx_quote.rtmr3.to_vec();

    // Load the list of environment secrets.
    let env_secrets_list: Vec<EnvSecret> =
        env_secrets_read(deps.storage).load()?;
    // Search for a secret with matching fields.
    for secret in env_secrets_list.into_iter() {
        if secret.mr_td == tdx_mr_td
            && secret.rtmr1 == tdx_rtmr1
            && secret.rtmr2 == tdx_rtmr2
            && secret.rtmr3 == tdx_rtmr3
        {
            return Ok(EnvSecretResponse {
                secrets_plaintext: secret.secrets_plaintext,
            });
        }
    }
    Err(StdError::generic_err(
        "No env secret found matching the attestation",
    ))
}

/// Returns information about a service by its ID.
fn query_service(deps: Deps, id: u64) -> StdResult<ServiceResponse> {
    let svc_list = services_read(deps.storage).load()?;
    let service = svc_list.into_iter().find(|s| s.id == id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    Ok(ServiceResponse {
        id: service.id,
        name: service.name,
        admin: service.admin.to_string(),
    })
}

/// Returns a list of all services.
fn query_services(deps: Deps) -> StdResult<Vec<ServiceResponse>> {
    let svc_list = services_read(deps.storage).load()?;
    let resp: Vec<ServiceResponse> = svc_list.into_iter().map(|s| ServiceResponse {
        id: s.id,
        name: s.name,
        admin: s.admin.to_string(),
    }).collect();
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
        let _ = instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();
        let exec_msg = ExecuteMsg::CreateService { name: "TestService".to_string() };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), exec_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "create_service"));
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetService { id: 0 }).unwrap();
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
        let create_msg = ExecuteMsg::CreateService { name: "ServiceWithImage".to_string() };
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
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: 0, image_filter: image_filter.clone() };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "add_image_to_service"));
        let remove_msg = ExecuteMsg::RemoveImageFromService { service_id: 0, image_filter };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "remove_image_from_service"));
    }

    #[test]
    fn get_secret_key() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForKey".to_string() };
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
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: 0, image_filter };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        // Construct a dummy quote buffer of size_of::<tdx_quote_t>()
        let quote_len = mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];
        // Set mr_td field in the quote.
        // tdx_quote_t layout: header (2+2+4+4+16+20 = 48 bytes), then tcb_svn (16), mr_seam (48), mr_signer_seam (48), seam_attributes (8), td_attributes (8), xfam (8), then mr_td (48).
        // mr_td offset = 48 + 16 + 48 + 48 + 8 + 8 + 8 = 184.
        let mr_td_offset = 184;
        quote[mr_td_offset..mr_td_offset+48].copy_from_slice(&expected_mr_td);
        // Dummy collateral
        let collateral = vec![0u8; 10];
        let get_msg = QueryMsg::GetSecretKey { service_id: 0, quote: quote.clone(), collateral: collateral.clone() };
        let res = query(deps.as_ref(), mock_env(), get_msg).unwrap();
        let secret_key: SecretKeyResponse = from_binary(&res).unwrap();
        assert_eq!(secret_key.encrypted_secret_key, "encrypted_secret_key");
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
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForFileKey".to_string() };
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
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: 0, image_filter };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();

        // Query the secret key using the quote and collateral read from file.
        let get_msg = QueryMsg::GetSecretKey { service_id: 0, quote, collateral };
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
        let create_msg = ExecuteMsg::CreateService { name: "UnauthorizedTest".to_string() };
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
        };
        let add_msg = ExecuteMsg::AddImageToService { service_id: 0, image_filter };
        let res = execute(deps.as_mut(), mock_env(), other_info.clone(), add_msg);
        match res {
            Err(StdError::GenericErr { msg, .. }) => {
                assert_eq!(msg, "Only the service admin can add image filter");
            },
            _ => panic!("Expected unauthorized error"),
        }
    }

    #[test]
    fn add_and_get_secret_key_by_image() {
        use std::fs;
        use std::path::Path;
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
        use cosmwasm_std::{from_binary, StdError};

        // Initialize dependencies and create the contract with an admin.
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // --- Step 1. Read quote and collateral from files.
        // (Assumes you have tests/quote.txt and tests/collateral.txt with valid hex strings.)
        let quote_path = Path::new("tests/quote.txt");
        let collateral_path = Path::new("tests/collateral.txt");
        let quote_hex = fs::read_to_string(quote_path)
            .expect("Failed to read quote.txt")
            .trim()
            .to_string();
        let collateral_hex = fs::read_to_string(collateral_path)
            .expect("Failed to read collateral.txt")
            .trim()
            .to_string();
        let quote = hex::decode(&quote_hex).expect("Failed to decode quote hex");
        let collateral = hex::decode(&collateral_hex).expect("Failed to decode collateral hex");

        // --- Step 2. Reconstruct the image filter from the attestation.
        // (This follows the same logic as in try_get_secret_key_by_image.)
        let tdx_quote = parse_tdx_attestation(&quote, &collateral)
            .expect("Attestation verification failed or quote invalid");
        let image_filter = MsgImageFilter {
            mr_seam: Some(tdx_quote.mr_seam.to_vec()),
            mr_signer_seam: Some(tdx_quote.mr_signer_seam.to_vec()),
            mr_td: Some(tdx_quote.mr_td.to_vec()),
            mr_config_id: Some(tdx_quote.mr_config_id.to_vec()),
            mr_owner: Some(tdx_quote.mr_owner.to_vec()),
            mr_config: Some(tdx_quote.mr_config.to_vec()),
            rtmr0: Some(tdx_quote.rtmr0.to_vec()),
            rtmr1: Some(tdx_quote.rtmr1.to_vec()),
            rtmr2: Some(tdx_quote.rtmr2.to_vec()),
            rtmr3: Some(tdx_quote.rtmr3.to_vec()),
        };

        // --- Step 3. Execute AddSecretKeyByImage to store a secret key for this image.
        let add_secret_msg = ExecuteMsg::AddSecretKeyByImage { image_filter: image_filter.clone() };
        let add_response = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_secret_msg).unwrap();
        assert!(add_response.attributes.iter().any(|attr| attr.key == "action" && attr.value == "add_secret_key_by_image"));

        // --- Step 4. Query GetSecretKeyByImage.
        let query_msg = QueryMsg::GetSecretKeyByImage { quote: quote.clone(), collateral: collateral.clone() };
        let query_response_bin = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let secret_key_response: SecretKeyResponse = from_binary(&query_response_bin).unwrap();

        // Check that we got a non-empty encrypted secret key and a public key.
        assert!(!secret_key_response.encrypted_secret_key.is_empty());
        assert!(!secret_key_response.encryption_pub_key.is_empty());

        println!("Encrypted secret key: {}", secret_key_response.encrypted_secret_key);
        println!("Encryption public key: {}", secret_key_response.encryption_pub_key);
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
        // Set up dependencies and initialize the contract.
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // First, add an environment secret using AddEnvByImage.
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
        };

        let add_env_msg = ExecuteMsg::AddEnvByImage {
            image_filter: image_filter.clone(),
            secrets_plaintext: "env_secret_plaintext".to_string(),
        };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_env_msg)
            .expect("AddEnvByImage execution failed");

        // Create a fake quote that meets the required attestation conditions.
        // Allocate a buffer of size equal to tdx_quote_t.
        let quote_len = mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];

        // Set header values:
        // version = 4 (little-endian)
        quote[0] = 4;
        quote[1] = 0;
        // tee_type = 0x81 in little-endian, starting from byte 4.
        quote[4] = 129;
        quote[5] = 0;
        quote[6] = 0;
        quote[7] = 0;

        // Set the mr_td field (bytes 184..232) to the value [10u8; 48]
        let mr_td_offset = 184;
        quote[mr_td_offset..mr_td_offset + 48].copy_from_slice(&[10u8; 48]);

        // Set rtmr1 field (bytes 424..472) to [20u8; 48]
        let rtmr1_offset = 424;
        quote[rtmr1_offset..rtmr1_offset + 48].copy_from_slice(&[20u8; 48]);

        // Set rtmr2 field (bytes 472..520) to [30u8; 48]
        let rtmr2_offset = 472;
        quote[rtmr2_offset..rtmr2_offset + 48].copy_from_slice(&[30u8; 48]);

        // Set rtmr3 field (bytes 520..568) to [40u8; 48]
        let rtmr3_offset = 520;
        quote[rtmr3_offset..rtmr3_offset + 48].copy_from_slice(&[40u8; 48]);

        // Fill report_data (bytes 568..632) first 32 bytes with non-zero values (required for extracting a public key)
        let report_data_offset = 568;
        for i in report_data_offset..(report_data_offset + 32) {
            quote[i] = 1;
        }

        // Create a dummy collateral (content not used in this test)
        let collateral = vec![0u8; 10];

        // Build the query message to retrieve the env secret.
        let query_msg = QueryMsg::GetEnvByImage {
            quote: quote.clone(),
            collateral: collateral.clone(),
        };

        // Query and deserialize the response.
        let res_bin = query(deps.as_ref(), mock_env(), query_msg)
            .expect("GetEnvByImage query failed");
        let env_secret_response: EnvSecretResponse = from_binary(&res_bin)
            .expect("Failed to deserialize EnvSecretResponse");

        // Print the response.
        println!("Env secret response: {:#?}", env_secret_response);

        // Verify that the returned plaintext matches the one set earlier.
        assert_eq!(env_secret_response.secrets_plaintext, "env_secret_plaintext".to_string());
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

}
