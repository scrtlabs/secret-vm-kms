use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, Event, attr, attr_plaintext};
use sha2::{Digest, Sha256};
use hex;
use core::mem;
#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
// use sha2::digest::Update;
use thiserror::Error;
use crate::amd_attest::{verify_amd_attestation, AmdAttestationMinimal, VerifiedAmdReport};
use crate::crypto::{KeyPair, SIVEncryptable, SECRET_KEY_SIZE};
use crate::msg::{EnvSecretResponse, ExecuteMsg, ImageFilterHex, ImageFilterHexEntry, InstantiateMsg, ListImageResponse, MigrateMsg, MsgImageFilter, QueryMsg, SecretKeyResponse, ServiceResponse, DockerCredentialsResponse, AmdMsgImageFilter, AmdListImageResponse, AmdImageFilterHexEntry};
use crate::state::{global_state, global_state_read, services, services_read, GlobalState, Service, ImageFilter, image_secret_keys, image_secret_keys_read, env_secrets, EnvSecret, env_secrets_read, SERVICES_MAP, FilterEntry, OldService, DockerCredential, docker_credentials, docker_credentials_read, OLD_SERVICES_MAP, OldFilterEntry, VM_RECORDS, VmRecord, DOCKER_CREDENTIALS, AMD_DOCKER_CREDENTIALS, AmdDockerCredential, AMD_VM_RECORDS, AmdImageFilter, AmdVmRecord, AMD_SERVICES_MAP, AmdFilterEntry, AmdService};
use crate::import_helpers::{from_high_half, from_low_half};
use crate::memory::{build_region, Region};
use crate::msg::QueryMsg::ListImageFilters;

// Fixed legacy MR_TD used to derive the legacy image_key (48 bytes).
// This is ONLY for the legacy fallback path in `try_get_secret_key_by_image`.
const LEGACY_FIXED_MR_TD: [u8; 48] = hex_literal::hex!(
    "ba87a347454466680bfd267446df89d8117c04ea9f28234dd3d84e1a8a957d5a
     daf02d4aa88433b559fb13bd40f0109e"
);

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
            // // Phase 1: load all old records into memory to avoid borrow issues
            // let mut buf: Vec<(String, OldService)> = Vec::new();
            // for it in OLD_SERVICES_MAP.iter(deps.storage)? {
            //     let (k, v) = it?;
            //     buf.push((k, v));
            // }
            //
            // let mut moved: u64 = 0;
            // let mut replaced: u64 = 0;
            //
            // // Phase 2: insert into SERVICES_MAP with password_hash=None
            // for (key, old) in buf.into_iter() {
            //     let new_svc = Service {
            //         id: old.id.clone(),
            //         name: old.name.clone(),
            //         admin: old.admin.clone(),
            //         filters: old.filters.clone(),
            //         secret_key: old.secret_key.clone(),
            //         secrets_plaintext: old.secrets_plaintext.clone(),
            //         password_hash: None, // new field default
            //     };
            //
            //     if SERVICES_MAP.contains(deps.storage, &key) {
            //         SERVICES_MAP.insert(deps.storage, &key, &new_svc)?;
            //         replaced += 1;
            //     } else {
            //         SERVICES_MAP.insert(deps.storage, &key, &new_svc)?;
            //         moved += 1;
            //     }
            //     // remove from OLD map after move
            //     OLD_SERVICES_MAP.remove(deps.storage, &key)?;
            // }

            Ok(Response::new()
                .add_attribute("action", "migrate"))
                // .add_attribute("moved", moved.to_string())
                // .add_attribute("replaced", replaced.to_string()))
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

// ---------------- Password helper ----------------
// If a password_hash is stored, the caller must provide `password` whose SHA256 hex equals the stored hash.
fn verify_password_opt(stored_hash_hex: &Option<String>, provided_password: &Option<String>) -> StdResult<()> {
    if let Some(expected_hex) = stored_hash_hex {
        let pwd = provided_password.as_ref().ok_or_else(|| StdError::generic_err("Password required"))?;
        let mut h = Sha256::new();
        h.update(pwd.as_bytes());
        let got_hex = hex::encode(h.finalize());
        if &got_hex != expected_hex {
            return Err(StdError::generic_err("Password mismatch"));
        }
    }
    Ok(())
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
        ExecuteMsg::CreateService { service_id, name, password_hash } =>
            try_create_service(deps,env, info, service_id, name, password_hash),
        ExecuteMsg::AddImageToService { service_id, image_filter, description, timestamp } =>
            try_add_filter(deps, env, info, service_id, image_filter, description, timestamp),
        ExecuteMsg::RemoveImageFromService { service_id, image_filter } =>
            try_remove_filter(deps, info, service_id, image_filter),
        ExecuteMsg::AddSecretKeyByImage { image_filter, password_hash } => {
            try_add_secret_key_by_image(deps, env, info, image_filter, password_hash)
        }
        // NEW: New operation to add or update an env secret by image.
        ExecuteMsg::AddEnvByImage { image_filter, secrets_plaintext, password_hash } => {
            try_add_env_by_image(deps, env, info, image_filter, secrets_plaintext, password_hash)
        }
        ExecuteMsg::AddDockerCredentialsByImage { image_filter, username, password_plaintext } => {
            try_add_docker_credentials_by_image(deps, env, info, image_filter, username, password_plaintext)
        }
        ExecuteMsg::AddEnvByService { service_id, secrets_plaintext } =>
            try_add_env_by_service(deps, env, info, service_id, secrets_plaintext),
        // --- AMD Handlers (New) ---
        ExecuteMsg::CreateAmdService { service_id, name, password_hash } =>
            try_create_amd_service(deps, env, info, service_id, name, password_hash),

        ExecuteMsg::AddAmdImageToService { service_id, image_filter, description, timestamp } =>
            try_add_amd_filter(deps, env, info, service_id, image_filter, description, timestamp),

        ExecuteMsg::AddAmdEnvByService { service_id, secrets_plaintext } =>
            try_add_amd_env_by_service(deps, env, info, service_id, secrets_plaintext),

        ExecuteMsg::AddAmdSecretKeyByImage { image_filter, password_hash } =>
            try_add_amd_secret_key_by_image(deps, env, info, image_filter, password_hash),

        ExecuteMsg::AddAmdEnvByImage { image_filter, secrets_plaintext, password_hash } =>
            try_add_amd_env_by_image(deps, env, info, image_filter, secrets_plaintext, password_hash),

        ExecuteMsg::AddAmdDockerCredentialsByImage { image_filter, username, password_plaintext } =>
            try_add_amd_docker_credentials_by_image(deps, env, info, image_filter, username, password_plaintext),
        ExecuteMsg::TestAmdVerification { report } =>
            try_test_amd_verification(deps, env, info, report),
    }
}

/// Unlike a query, this consumes gas and records the result in the blockchain transaction logs (events).
/// It will revert the transaction if verification fails.
fn try_test_amd_verification(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    report_b64: String,
) -> StdResult<Response> {
    // 1. Wrap the base64 input string into the struct expected by the verifier logic.
    let att = AmdAttestationMinimal { report_b64 };

    // 2. Call the core verification logic imported from `amd_attest.rs`.
    // If verification fails (invalid signature, wrong chain, etc.), this returns an Err,
    // which stops execution and reverts the transaction.
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    // 3. Encode the raw byte arrays (measurement and report_data) into Hex strings.
    // This makes them human-readable in the transaction response/logs.
    let measurement_hex = hex::encode(verified.measurement);
    let report_data_hex = hex::encode(verified.report_data);

    // 4. Construct the successful response.
    // We add the extracted data as attributes so the caller can verify what the contract "sees".
    Ok(Response::new()
        .add_attribute("action", "test_amd_verification")
        .add_attribute("status", "success")
        .add_attribute("measurement", measurement_hex)
        .add_attribute("report_data", report_data_hex))
}

// -----------------------------------------------------------------------------
// AMD EXECUTE HANDLERS
// -----------------------------------------------------------------------------

/// Create a new AMD Service.
fn try_create_amd_service(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_id: String,
    name: String,
    password_hash: Option<String>,
) -> StdResult<Response> {
    // Check for existing service_id in AMD map
    if AMD_SERVICES_MAP.contains(deps.storage, &service_id) {
        return Err(StdError::generic_err("AMD Service ID exists"));
    }

    // Compute secret_key (same logic as TDX, but independent)
    let mut hasher = Sha256::new();
    let mut random_bytes = Vec::new();
    for bin in env.block.random.iter() {
        random_bytes.extend_from_slice(bin.as_slice());
    }
    sha2::Digest::update(&mut hasher, &random_bytes);
    sha2::Digest::update(&mut hasher, service_id.as_bytes());
    let secret_key = hasher.finalize().to_vec();

    let svc = AmdService {
        id: service_id.clone(),
        name: name.clone(),
        admin: info.sender.clone(),
        secret_key,
        filters: Vec::new(),
        secrets_plaintext: None,
        password_hash,
    };

    AMD_SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;

    Ok(Response::new()
        .add_attribute("action","create_amd_service")
        .add_attribute("service_id",service_id)
        .add_attribute("name",name))
}

/// Add Env secret to AMD Service.
fn try_add_amd_env_by_service(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    service_id: String,
    secrets_plaintext: String,
) -> StdResult<Response> {
    let mut svc = AMD_SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("AMD Service not found"))?;

    if info.sender.to_string() != svc.admin {
        return Err(StdError::generic_err("Only the service admin can add service env secret"));
    }

    svc.secrets_plaintext = Some(secrets_plaintext);
    AMD_SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;

    Ok(Response::new()
        .add_attribute("action", "add_amd_env_by_service")
        .add_attribute("service_id", service_id)
        .add_attribute("updated", "true"))
}

/// Add Filter to AMD Service.
fn try_add_amd_filter(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_id: String,
    image_filter: AmdMsgImageFilter,
    description: String,
    timestamp: Option<u64>,
) -> StdResult<Response> {
    let mut svc = AMD_SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("AMD Service not found"))?;

    if info.sender.to_string() != svc.admin {
        return Err(StdError::generic_err("Only the service admin can add image filter"));
    }

    let entry_filter = AmdImageFilter {
        measurement: image_filter.measurement.clone(),
    };

    let ts_to_store = timestamp.or(Some(env.block.time.seconds()));

    svc.filters.push(AmdFilterEntry {
        filter: entry_filter.clone(),
        description: description.clone(),
        timestamp: ts_to_store,
    });

    AMD_SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;

    Ok(Response::new()
        .add_attribute("action", "add_amd_image_to_service")
        .add_attribute("service_id", service_id))
}

/// Add Secret Key by Image (VM-based) for AMD.
fn try_add_amd_secret_key_by_image(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    image_filter: AmdMsgImageFilter,
    password_hash: Option<String>,
) -> StdResult<Response> {
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add a VM secret key"));
    }
    let vm_uid = image_filter.vm_uid.ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    // Derive key
    let mut key_hasher = Sha256::new();
    for bin in env.block.random.iter() { key_hasher.update(bin.as_slice()); }
    if let Some(v) = &image_filter.measurement { key_hasher.update(v); }
    key_hasher.update(&vm_uid);
    let secret_hex = hex::encode(key_hasher.finalize());

    let f = AmdImageFilter { measurement: image_filter.measurement };

    let mut updated = false;
    let rec = if let Some(mut r) = AMD_VM_RECORDS.get(deps.storage, &vm_uid) {
        r.filter = f;
        r.secret_key_hex = Some(secret_hex);
        if password_hash.is_some() { r.password_hash = password_hash; }
        updated = true;
        r
    } else {
        AmdVmRecord { filter: f, secret_key_hex: Some(secret_hex), env_plaintext: None, password_hash }
    };

    AMD_VM_RECORDS.insert(deps.storage, &vm_uid, &rec)?;
    Ok(Response::new().add_attribute("action","add_amd_secret_key_by_image").add_attribute("updated", updated.to_string()))
}

/// Add Env by Image (VM-based) for AMD.
fn try_add_amd_env_by_image(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    image_filter: AmdMsgImageFilter,
    secrets_plaintext: String,
    password_hash: Option<String>,
) -> StdResult<Response> {
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add env for VM"));
    }
    let vm_uid = image_filter.vm_uid.ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    let f = AmdImageFilter { measurement: image_filter.measurement };

    let mut updated = false;
    let rec = if let Some(mut r) = AMD_VM_RECORDS.get(deps.storage, &vm_uid) {
        r.filter = f;
        r.env_plaintext = Some(secrets_plaintext);
        if password_hash.is_some() { r.password_hash = password_hash; }
        updated = true;
        r
    } else {
        AmdVmRecord { filter: f, secret_key_hex: None, env_plaintext: Some(secrets_plaintext), password_hash }
    };

    AMD_VM_RECORDS.insert(deps.storage, &vm_uid, &rec)?;
    Ok(Response::new().add_attribute("action","add_amd_env_by_image").add_attribute("updated", updated.to_string()))
}

/// Add Docker Creds (VM-based) for AMD.
fn try_add_amd_docker_credentials_by_image(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    image_filter: AmdMsgImageFilter,
    username: String,
    password_plaintext: String,
) -> StdResult<Response> {
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add docker credentials"));
    }

    let vm_uid = image_filter.vm_uid.ok_or_else(|| StdError::generic_err("vm_uid required"))?;
    let measurement = image_filter.measurement.ok_or_else(|| StdError::generic_err("measurement required"))?;

    let new_rec = AmdDockerCredential {
        measurement: measurement.clone(),
        vm_uid: Some(vm_uid.clone()),
        docker_username: username.clone(),
        docker_password_plaintext: password_plaintext.clone(),
    };

    let mut updated = false;
    if let Some(mut existing) = AMD_DOCKER_CREDENTIALS.get(deps.storage, &vm_uid) {
        existing.measurement = new_rec.measurement.clone();
        existing.docker_username = new_rec.docker_username.clone();
        existing.docker_password_plaintext = new_rec.docker_password_plaintext.clone();
        AMD_DOCKER_CREDENTIALS.insert(deps.storage, &vm_uid, &existing)?;
        updated = true;
    } else {
        AMD_DOCKER_CREDENTIALS.insert(deps.storage, &vm_uid, &new_rec)?;
    }

    Ok(Response::new()
        .add_attribute("action", "add_amd_docker_credentials_by_image")
        .add_attribute("updated", updated.to_string()))
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
    // Only global admin can add docker credentials
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add docker credentials"));
    }

    // vm_uid is REQUIRED (we store by vm_uid)
    let vm_uid = image_filter
        .vm_uid
        .ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    // Pin to exact image values
    if image_filter.mr_td.is_none()
        || image_filter.rtmr1.is_none()
        || image_filter.rtmr2.is_none()
        || image_filter.rtmr3.is_none()
    {
        return Err(StdError::generic_err(
            "Missing required fields in ImageFilter (mr_td, rtmr1, rtmr2, rtmr3 required)",
        ));
    }

    let new_rec = DockerCredential {
        mr_td: image_filter.mr_td.clone().unwrap(),
        rtmr1: image_filter.rtmr1.clone().unwrap(),
        rtmr2: image_filter.rtmr2.clone().unwrap(),
        rtmr3: image_filter.rtmr3.clone().unwrap(),
        vm_uid: Some(vm_uid.clone()),
        docker_username: username.clone(),
        docker_password_plaintext: password_plaintext.clone(),
    };

    // Write/update in the VM-keyed map
    let mut updated = false;
    if let Some(mut existing) = DOCKER_CREDENTIALS.get(deps.storage, &vm_uid) {
        // Overwrite to keep latest filter+creds
        existing.mr_td = new_rec.mr_td.clone();
        existing.rtmr1 = new_rec.rtmr1.clone();
        existing.rtmr2 = new_rec.rtmr2.clone();
        existing.rtmr3 = new_rec.rtmr3.clone();
        existing.docker_username = new_rec.docker_username.clone();
        existing.docker_password_plaintext = new_rec.docker_password_plaintext.clone();
        DOCKER_CREDENTIALS.insert(deps.storage, &vm_uid, &existing)?;
        updated = true;
    } else {
        DOCKER_CREDENTIALS.insert(deps.storage, &vm_uid, &new_rec)?;
    }

    // We do NOT write to the legacy vector; query has a legacy reverse-scan fallback.
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
    password_hash: Option<String>,
) -> StdResult<Response> {
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add env for VM"));
    }
    let vm_uid = image_filter.vm_uid.ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    let f = ImageFilter {
        mr_seam: image_filter.mr_seam, mr_signer_seam: image_filter.mr_signer_seam,
        mr_td: image_filter.mr_td, mr_config_id: image_filter.mr_config_id, mr_owner: image_filter.mr_owner,
        mr_config: image_filter.mr_config, rtmr0: image_filter.rtmr0, rtmr1: image_filter.rtmr1,
        rtmr2: image_filter.rtmr2, rtmr3: image_filter.rtmr3,
    };

    let mut updated = false;
    let rec = if let Some(mut r) = VM_RECORDS.get(deps.storage, &vm_uid) {
        r.filter = f;
        r.env_plaintext = Some(secrets_plaintext);
        if password_hash.is_some() { r.password_hash = password_hash; }
        updated = true;
        r
    } else {
        VmRecord { filter: f, secret_key_hex: None, env_plaintext: Some(secrets_plaintext), password_hash }
    };

    VM_RECORDS.insert(deps.storage, &vm_uid, &rec)?;
    Ok(Response::new().add_attribute("action","add_env_by_image").add_attribute("updated", updated.to_string()))
}

// Unified VM: Add secret key under VM_RECORDS (keyed by vm_uid)
fn try_add_secret_key_by_image(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    image_filter: MsgImageFilter,
    password_hash: Option<String>,
) -> StdResult<Response> {
    let gs = global_state_read(deps.storage).load()?;
    if info.sender != gs.admin {
        return Err(StdError::generic_err("Only the admin can add a VM secret key"));
    }
    let vm_uid = image_filter.vm_uid.ok_or_else(|| StdError::generic_err("vm_uid required"))?;

    // Derive deterministic secret hex using randomness + key fields
    let mut key_hasher = Sha256::new();
    for bin in env.block.random.iter() { key_hasher.update(bin.as_slice()); }
    if let Some(v) = &image_filter.mr_td   { key_hasher.update(v); }
    if let Some(v) = &image_filter.rtmr1   { key_hasher.update(v); }
    if let Some(v) = &image_filter.rtmr2   { key_hasher.update(v); }
    if let Some(v) = &image_filter.rtmr3   { key_hasher.update(v); }
    key_hasher.update(&vm_uid);
    let secret_hex = hex::encode(key_hasher.finalize());

    let f = ImageFilter {
        mr_seam: image_filter.mr_seam, mr_signer_seam: image_filter.mr_signer_seam,
        mr_td: image_filter.mr_td, mr_config_id: image_filter.mr_config_id, mr_owner: image_filter.mr_owner,
        mr_config: image_filter.mr_config, rtmr0: image_filter.rtmr0, rtmr1: image_filter.rtmr1,
        rtmr2: image_filter.rtmr2, rtmr3: image_filter.rtmr3,
    };

    let mut updated = false;
    let rec = if let Some(mut r) = VM_RECORDS.get(deps.storage, &vm_uid) {
        r.filter = f;
        r.secret_key_hex = Some(secret_hex);
        if password_hash.is_some() { r.password_hash = password_hash; }
        updated = true;
        r
    } else {
        VmRecord { filter: f, secret_key_hex: Some(secret_hex), env_plaintext: None, password_hash }
    };

    VM_RECORDS.insert(deps.storage, &vm_uid, &rec)?;
    Ok(Response::new().add_attribute("action","add_secret_key_by_image_vm").add_attribute("updated", updated.to_string()))
}

/// Create service: generate secret_key via SHA256(env.random + id)
/// The sender becomes the service admin
fn try_create_service(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_id: String,
    name: String,
    password_hash: Option<String>,
) -> StdResult<Response> {
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
    // The sender becomes the service admin
    let svc = Service { id: service_id.clone(), name: name.clone(), admin: info.sender.clone(), secret_key, filters: Vec::new(), secrets_plaintext: None, password_hash,};
    SERVICES_MAP.insert(deps.storage, &service_id, &svc)?;
    Ok(Response::new().add_attribute("action","create_service").add_attribute("service_id",service_id).add_attribute("name",name))
}

/// Add filter
fn try_add_filter(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_id: String,
    image_filter: MsgImageFilter,
    description: String,
    timestamp: Option<u64>,
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

    // Decide the timestamp to store:
    // - if provided in the message, use it
    // - otherwise, use current block time (seconds)
    // (legacy entries will remain `None` after migration)
    let ts_to_store = timestamp.or(Some(env.block.time.seconds()));

    // Add new filter entry
    svc.filters.push(FilterEntry { filter: entry_filter.clone(), description: description.clone() ,timestamp: ts_to_store,  });
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

    if let Some(ts) = ts_to_store {
        ev = ev.add_attribute_plaintext("timestamp", ts.to_string());
    }
    if let Some(ts) = ts_to_store {
        resp = resp.add_attribute("timestamp", ts.to_string());
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
    password: Option<String>,
) -> StdResult<SecretKeyResponse> {
    let svc = SERVICES_MAP.get(deps.storage, &service_id).ok_or_else(|| StdError::generic_err("Service not found"))?;
    verify_password_opt(&svc.password_hash, &password)?;

    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Invalid attestation"))?;

    // match against any service filter
    let mut found = false;
    for entry in svc.filters.iter() {
        if filter_matches_quote(&entry.filter, &tdx) { found = true; break; }
    }
    if !found { return Err(StdError::generic_err("No matching image filter found")); }

    let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Invalid report_data"))?;
    encrypt_secret(svc.secret_key.clone(), other_pub, &quote, env.block.height.to_string().into_bytes())
}

pub fn try_get_secret_key_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
    password: Option<String>,
) -> StdResult<SecretKeyResponse> {
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;
    let vm_uid = tdx.report_data[32..48].to_vec();

    if let Some(rec) = VM_RECORDS.get(deps.storage, &vm_uid) {
        verify_password_opt(&rec.password_hash, &password)?;
        if !filter_matches_quote(&rec.filter, &tdx) {
            return Err(StdError::generic_err("Filter mismatch for VM record"));
        }
        let secret_hex = rec.secret_key_hex.ok_or_else(|| StdError::generic_err("Secret key not set for this VM"))?;
        let secret_bytes = hex::decode(secret_hex).map_err(|_| StdError::generic_err("Stored secret malformed"))?;
        let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Bad report_data"))?;
        return encrypt_secret(secret_bytes, other_pub, &quote, env.block.height.to_string().into_bytes());
    }

    // Legacy fallback by image hash (no password for legacy)
    // NOTE: historically, `mr_td` in the legacy pipeline was always a fixed value.
    // To preserve compatibility, we DO NOT use `tdx.mr_td` here; we hash with the fixed legacy MR_TD.
    let mut hasher = Sha256::new();
    // IMPORTANT: use the fixed legacy MR_TD constant instead of the parsed mr_td
    hasher.update(&LEGACY_FIXED_MR_TD);
    hasher.update(&tdx.rtmr1);
    hasher.update(&tdx.rtmr2);
    hasher.update(&tdx.rtmr3);
    let image_key = hasher.finalize().to_vec();

    let bucket = image_secret_keys_read(deps.storage);
    let secret_hex = bucket.load(&image_key)
        .map_err(|_| StdError::generic_err("Secret key for this image has not been created"))?;
    let secret_bytes = hex::decode(&secret_hex).map_err(|_| StdError::generic_err("Stored secret is malformed"))?;
    let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Bad report_data"))?;
    encrypt_secret(secret_bytes, other_pub, &quote, env.block.height.to_string().into_bytes())
}


/// Query entry point for handling QueryMsg.
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetService { id } => to_binary(&query_service(deps, id)?),
        QueryMsg::ListServices {} => to_binary(&query_services(deps)?),
        QueryMsg::GetSecretKey { service_id, quote, collateral, password } => {
            to_binary(&try_get_secret_key(deps, env.clone(), service_id, quote, collateral, password)?)
        }
        QueryMsg::GetSecretKeyByImage { quote, collateral, password } => {
            to_binary(&try_get_secret_key_by_image(deps, env, quote, collateral, password)?)
        }
        // NEW: Operation to retrieve env secret by image.
        QueryMsg::GetEnvByImage { quote, collateral,password  } => {
            to_binary(&try_get_env_by_image(deps, env, quote, collateral,password)?)
        }
        QueryMsg::GetDockerCredentialsByImage { quote, collateral } => {
            to_binary(&try_get_docker_credentials_by_image(deps, env, quote, collateral)?)
        }
        /// Return filters (with descriptions) for a service
        ListImageFilters { service_id} =>  {
            to_binary(&query_image_filters(deps, service_id)?)
        }
        QueryMsg::GetEnvByService { service_id, quote, collateral, password } =>
            to_binary(&try_get_env_by_service(deps, env, service_id, quote, collateral, password)?),

        // --- AMD Queries (Strictly AMD Maps) ---
        QueryMsg::GetAmdService { id } => to_binary(&query_amd_service(deps, id)?),
        QueryMsg::ListAmdServices {} => to_binary(&query_amd_services(deps)?),
        QueryMsg::ListAmdImageFilters { service_id } => to_binary(&query_amd_image_filters(deps, service_id)?),

        QueryMsg::GetSecretKeyAmd { service_id, report, password } =>
            to_binary(&try_get_secret_key_amd(deps, env, service_id, report, password)?),
        QueryMsg::GetSecretKeyByImageAmd { report, password } =>
            to_binary(&try_get_secret_key_by_image_amd(deps, env, report, password)?),
        QueryMsg::GetEnvByImageAmd { report, password } =>
            to_binary(&try_get_env_by_image_amd(deps, env, report, password)?),
        QueryMsg::GetDockerCredentialsByImageAmd { report } =>
            to_binary(&try_get_docker_credentials_by_image_amd(deps, env, report)?),
        QueryMsg::GetEnvByServiceAmd { service_id, report, password } =>
            to_binary(&try_get_env_by_service_amd(deps, env, service_id, report, password)?),
    }
}

// --- AMD Basic Queries ---

fn query_amd_service(deps: Deps, id: String) -> StdResult<ServiceResponse> {
    let svc = AMD_SERVICES_MAP
        .get(deps.storage, &id)
        .ok_or_else(|| StdError::generic_err("AMD Service not found"))?;
    Ok(ServiceResponse { id: svc.id, name: svc.name, admin: svc.admin.into_string() })
}

fn query_amd_services(deps: Deps) -> StdResult<Vec<ServiceResponse>> {
    let mut resp: Vec<ServiceResponse> = Vec::new();
    for result in AMD_SERVICES_MAP.iter(deps.storage)? {
        let (_key, svc) = result?;
        resp.push(ServiceResponse {
            id: svc.id.clone(),
            name: svc.name.clone(),
            admin: svc.admin.clone().into_string(),
        });
    }
    Ok(resp)
}

fn query_amd_image_filters(deps: Deps, service_id: String) -> StdResult<AmdListImageResponse> {
    let svc = AMD_SERVICES_MAP
        .get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("AMD Service not found"))?;

    let list = svc.filters.iter().map(|entry| {
        let f = &entry.filter;
        AmdImageFilterHexEntry {
            measurement: f.measurement.as_ref().map(|b| hex::encode(b)),
            description: entry.description.clone(),
            timestamp: entry.timestamp,
        }
    }).collect();

    Ok(AmdListImageResponse { service_id, filters: list })
}

// --- AMD Verification Logic ---

fn amd_filter_matches(f: &AmdImageFilter, verified: &VerifiedAmdReport) -> bool {
    if let Some(m) = &f.measurement {
        if m != &verified.measurement.to_vec() {
            return false;
        }
    }
    true
}

// 1. Get Service Secret Key (AMD)
fn try_get_secret_key_amd(
    deps: Deps,
    env: Env,
    service_id: String,
    report_b64: String,
    password: Option<String>,
) -> StdResult<SecretKeyResponse> {
    // 1. Verify Report
    let att = AmdAttestationMinimal { report_b64: report_b64.clone() };
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    // 2. Load Service from AMD Map
    let svc = AMD_SERVICES_MAP.get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("Service not found in AMD map"))?;

    verify_password_opt(&svc.password_hash, &password)?;

    // 3. Match Filter
    let mut found = false;
    for entry in svc.filters.iter() {
        if amd_filter_matches(&entry.filter, &verified) { found = true; break; }
    }
    if !found { return Err(StdError::generic_err("No matching image filter found")); }

    // 4. Encrypt
    let other_pub: [u8;32] = verified.report_data[0..32].try_into().unwrap();
    let report_bytes = base64::decode(&report_b64).map_err(|_| StdError::generic_err("base64 decode"))?;

    encrypt_secret(svc.secret_key.clone(), other_pub, &report_bytes, env.block.height.to_string().into_bytes())
}

// 2. Get Secret Key By Image (AMD)
fn try_get_secret_key_by_image_amd(
    deps: Deps,
    env: Env,
    report_b64: String,
    password: Option<String>,
) -> StdResult<SecretKeyResponse> {
    let att = AmdAttestationMinimal { report_b64: report_b64.clone() };
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    let vm_uid = verified.report_data[32..48].to_vec();

    if let Some(rec) = AMD_VM_RECORDS.get(deps.storage, &vm_uid) {
        verify_password_opt(&rec.password_hash, &password)?;
        if !amd_filter_matches(&rec.filter, &verified) {
            return Err(StdError::generic_err("Filter mismatch for VM record"));
        }
        let secret_hex = rec.secret_key_hex.ok_or_else(|| StdError::generic_err("Secret key not set for this VM"))?;
        let secret_bytes = hex::decode(secret_hex).map_err(|_| StdError::generic_err("Stored secret malformed"))?;

        let other_pub: [u8;32] = verified.report_data[0..32].try_into().unwrap();
        let report_bytes = base64::decode(&report_b64).map_err(|_| StdError::generic_err("base64 decode"))?;

        return encrypt_secret(secret_bytes, other_pub, &report_bytes, env.block.height.to_string().into_bytes());
    }

    Err(StdError::generic_err("Secret key for this image has not been created"))
}

// 3. Get Env By Image (AMD)
fn try_get_env_by_image_amd(
    deps: Deps,
    env: Env,
    report_b64: String,
    password: Option<String>,
) -> StdResult<EnvSecretResponse> {
    let att = AmdAttestationMinimal { report_b64: report_b64.clone() };
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    let vm_uid = verified.report_data[32..48].to_vec();

    if let Some(rec) = AMD_VM_RECORDS.get(deps.storage, &vm_uid) {
        verify_password_opt(&rec.password_hash, &password)?;
        if !amd_filter_matches(&rec.filter, &verified) {
            return Err(StdError::generic_err("Filter mismatch for VM record"));
        }
        let plain = rec.env_plaintext.ok_or_else(|| StdError::generic_err("Env secret not set for this VM"))?;

        let other_pub: [u8;32] = verified.report_data[0..32].try_into().unwrap();
        let report_bytes = base64::decode(&report_b64).map_err(|_| StdError::generic_err("base64 decode"))?;

        let enc = encrypt_secret(plain.into_bytes(), other_pub, &report_bytes, env.block.height.to_string().into_bytes())?;
        return Ok(EnvSecretResponse { encrypted_secrets_plaintext: enc.encrypted_secret_key, encryption_pub_key: enc.encryption_pub_key });
    }

    Err(StdError::generic_err("No env secret found"))
}

// 4. Get Docker Credentials (AMD)
fn try_get_docker_credentials_by_image_amd(
    deps: Deps,
    env: Env,
    report_b64: String,
) -> StdResult<DockerCredentialsResponse> {
    let att = AmdAttestationMinimal { report_b64: report_b64.clone() };
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    let vm_uid = verified.report_data[32..48].to_vec();
    let measurement = verified.measurement.to_vec();

    if let Some(rec) = AMD_DOCKER_CREDENTIALS.get(deps.storage, &vm_uid) {
        if rec.measurement != measurement {
            return Err(StdError::generic_err("Filter mismatch for docker credentials VM record"));
        }

        let other_pub: [u8;32] = verified.report_data[0..32].try_into().unwrap();
        let report_bytes = base64::decode(&report_b64).map_err(|_| StdError::generic_err("base64 decode"))?;
        let height_bytes = env.block.height.to_string().into_bytes();

        return encrypt_docker_credentials(
            rec.docker_username,
            rec.docker_password_plaintext,
            other_pub,
            &report_bytes,
            height_bytes,
        );
    }

    Err(StdError::generic_err("No docker credentials found for this image"))
}

// 5. Get Env By Service (AMD) - Reads AMD_SERVICES_MAP
fn try_get_env_by_service_amd(
    deps: Deps,
    env: Env,
    service_id: String,
    report_b64: String,
    password: Option<String>,
) -> StdResult<EnvSecretResponse> {
    let att = AmdAttestationMinimal { report_b64: report_b64.clone() };
    let verified = verify_amd_attestation(&att)
        .map_err(|e| StdError::generic_err(format!("AMD Verification failed: {:?}", e)))?;

    let svc = AMD_SERVICES_MAP.get(deps.storage, &service_id)
        .ok_or_else(|| StdError::generic_err("AMD Service not found"))?;

    verify_password_opt(&svc.password_hash, &password)?;

    let mut found = false;
    for entry in svc.filters.iter() {
        if amd_filter_matches(&entry.filter, &verified) { found = true; break; }
    }
    if !found { return Err(StdError::generic_err("No matching image filter found")); }

    let plaintext = svc.secrets_plaintext.clone().ok_or_else(|| StdError::generic_err("Env secret for this service not set"))?;

    let other_pub: [u8;32] = verified.report_data[0..32].try_into().unwrap();
    let report_bytes = base64::decode(&report_b64).map_err(|_| StdError::generic_err("base64 decode"))?;

    let enc = encrypt_secret(plaintext.into_bytes(), other_pub, &report_bytes, env.block.height.to_string().into_bytes())?;
    Ok(EnvSecretResponse { encrypted_secrets_plaintext: enc.encrypted_secret_key, encryption_pub_key: enc.encryption_pub_key })
}

// Helper: filter match vs parsed TDX
fn filter_matches_quote(f: &ImageFilter, tdx: &tdx_quote_t) -> bool {
    let mr_seam = tdx.mr_seam.to_vec();
    let mr_signer = tdx.mr_signer_seam.to_vec();
    let mr_config_id = tdx.mr_config_id.to_vec();
    let mr_owner = tdx.mr_owner.to_vec();
    let mr_config = tdx.mr_config.to_vec();
    let rtmr0 = tdx.rtmr0.to_vec();
    let rtmr1 = tdx.rtmr1.to_vec();
    let rtmr2 = tdx.rtmr2.to_vec();
    let rtmr3 = tdx.rtmr3.to_vec();

    if let Some(p) = &f.mr_seam        { if p != &mr_seam   { return false; } }
    if let Some(p) = &f.mr_signer_seam { if p != &mr_signer { return false; } }
    // if let Some(p) = &f.mr_td          { if p != &mr_td     { return false; } }
    if let Some(p) = &f.mr_config_id   { if p != &mr_config_id { return false; } }
    if let Some(p) = &f.mr_owner       { if p != &mr_owner  { return false; } }
    if let Some(p) = &f.mr_config      { if p != &mr_config { return false; } }
    if let Some(p) = &f.rtmr0          { if p != &rtmr0     { return false; } }
    if let Some(p) = &f.rtmr1          { if p != &rtmr1     { return false; } }
    if let Some(p) = &f.rtmr2          { if p != &rtmr2     { return false; } }
    if let Some(p) = &f.rtmr3          { if p != &rtmr3     { return false; } }
    true
}

/// handler for retrieving service-level secret
pub fn try_get_env_by_service(
    deps: Deps,
    env: Env,
    service_id: String,
    quote: Vec<u8>,
    collateral: Vec<u8>,
    password: Option<String>,
) -> StdResult<EnvSecretResponse> {
    let svc = SERVICES_MAP.get(deps.storage, &service_id).ok_or_else(|| StdError::generic_err("Service not found"))?;
    verify_password_opt(&svc.password_hash, &password)?;

    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;

    let mut found = false;
    for entry in svc.filters.iter() {
        if filter_matches_quote(&entry.filter, &tdx) { found = true; break; }
    }
    if !found { return Err(StdError::generic_err("No matching image filter found")); }

    let plaintext = svc.secrets_plaintext.clone().ok_or_else(|| StdError::generic_err("Env secret for this service not set"))?;
    let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Bad report_data"))?;
    let enc = encrypt_secret(plaintext.into_bytes(), other_pub, &quote, env.block.height.to_string().into_bytes())?;
    Ok(EnvSecretResponse { encrypted_secrets_plaintext: enc.encrypted_secret_key, encryption_pub_key: enc.encryption_pub_key })
}

pub fn try_get_docker_credentials_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
) -> StdResult<DockerCredentialsResponse> {
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;

    // Fields from quote
    let r1 = tdx.rtmr1.to_vec();
    let r2 = tdx.rtmr2.to_vec();
    let r3 = tdx.rtmr3.to_vec();
    let vm_uid = tdx.report_data[32..48].to_vec(); // 16 bytes after pubkey

    // 1) Primary lookup: VM-keyed map
    if let Some(rec) = DOCKER_CREDENTIALS.get(deps.storage, &vm_uid) {
        // Enforce exact match between stored image params and attestation
        if rec.rtmr1 != r1 || rec.rtmr2 != r2 || rec.rtmr3 != r3 {
            return Err(StdError::generic_err(
                "Filter mismatch for docker credentials VM record",
            ));
        }
        let other_pub: [u8; 32] = tdx.report_data[0..32]
            .try_into()
            .map_err(|_| StdError::generic_err("Bad report_data"))?;
        let height_bytes = env.block.height.to_string().into_bytes();
        return encrypt_docker_credentials(
            rec.docker_username,
            rec.docker_password_plaintext,
            other_pub,
            &quote,
            height_bytes,
        );
    }

    // 2) Legacy fallback: scan the old Vec from the END (last-write wins)
    let legacy_list = docker_credentials_read(deps.storage).load().unwrap_or_default();
    if let Some(rec) = legacy_list.iter().rev().find(|cred| {
            cred.rtmr1 == r1
            && cred.rtmr2 == r2
            && cred.rtmr3 == r3
            && cred.vm_uid
            .as_ref()
            .map(|v| v == &vm_uid)
            .unwrap_or(true) // legacy may have vm_uid=None
    }) {
        let other_pub: [u8; 32] = tdx.report_data[0..32]
            .try_into()
            .map_err(|_| StdError::generic_err("Bad report_data"))?;
        let height_bytes = env.block.height.to_string().into_bytes();
        return encrypt_docker_credentials(
            rec.docker_username.clone(),
            rec.docker_password_plaintext.clone(),
            other_pub,
            &quote,
            height_bytes,
        );
    }

    Err(StdError::generic_err(
        "No docker credentials found for this image",
    ))
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
            timestamp: entry.timestamp,
        }
    }).collect();

    Ok(ListImageResponse {service_id,  filters: list })
}

/// NEW: Retrieve the environment secret using an attestation.
/// This function verifies the provided quote and collateral, parses the attestation to extract
/// mr_td, rtmr1, rtmr2, and rtmr3, and then searches for an env secret with matching fields.
pub fn try_get_env_by_image(
    deps: Deps,
    env: Env,
    quote: Vec<u8>,
    collateral: Vec<u8>,
    password: Option<String>,
) -> StdResult<EnvSecretResponse> {
    let tdx = parse_tdx_attestation(&quote, &collateral)
        .ok_or_else(|| StdError::generic_err("Attestation invalid"))?;
    let vm_uid = tdx.report_data[32..48].to_vec();

    if let Some(rec) = VM_RECORDS.get(deps.storage, &vm_uid) {
        verify_password_opt(&rec.password_hash, &password)?;
        if !filter_matches_quote(&rec.filter, &tdx) {
            return Err(StdError::generic_err("Filter mismatch for VM record"));
        }
        let plain = rec.env_plaintext.ok_or_else(|| StdError::generic_err("Env secret not set for this VM"))?;
        let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Bad report_data"))?;
        let enc = encrypt_secret(plain.into_bytes(), other_pub, &quote, env.block.height.to_string().into_bytes())?;
        return Ok(EnvSecretResponse { encrypted_secrets_plaintext: enc.encrypted_secret_key, encryption_pub_key: enc.encryption_pub_key });
    }

    // Legacy fallback (scan vector)
    let legacy = env_secrets_read(deps.storage).load().map_err(|_| StdError::generic_err("Legacy env storage missing"))?;
    let r1 = tdx.rtmr1.to_vec(); let r2 = tdx.rtmr2.to_vec(); let r3 = tdx.rtmr3.to_vec();
    let candidate = legacy
        .iter()
        .rev()
        .find(|e| {
                e.rtmr1 == r1
                && e.rtmr2 == r2
                && e.rtmr3 == r3
                && e.vm_uid
                .as_ref()
                .map(|v| v == &vm_uid)
                .unwrap_or(true) // legacy may have vm_uid = None
        })
        .cloned() // we iter() above, so clone the found EnvSecret
        .ok_or_else(|| StdError::generic_err("No env secret found"))?;

    let other_pub: [u8;32] = tdx.report_data[0..32].try_into().map_err(|_| StdError::generic_err("Bad report_data"))?;
    let enc = encrypt_secret(candidate.secrets_plaintext.into_bytes(), other_pub, &quote, env.block.height.to_string().into_bytes())?;
    Ok(EnvSecretResponse { encrypted_secrets_plaintext: enc.encrypted_secret_key, encryption_pub_key: enc.encryption_pub_key })
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
    use cosmwasm_std::VoteOption::No;

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
            password_hash: None,
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
        let create_msg = ExecuteMsg::CreateService {service_id: "0".to_string(), name: "ServiceWithImage".to_string(), password_hash: None};
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
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), image_filter: image_filter.clone(), description: "TestImage".to_string(), timestamp: None};
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
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForKey".to_string(), service_id: "0".to_string(), password_hash: None};
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
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), image_filter, description: "TestImage".to_string(), timestamp: None };
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
        let get_msg = QueryMsg::GetSecretKey { service_id: "0".to_string(), quote: quote.clone(), collateral: collateral.clone(), password: None };
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
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForFileKey".to_string(), service_id: "0".to_string(), password_hash: None};
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
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), description: "TestImage".to_string(), image_filter, timestamp: None };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();

        // Query the secret key using the quote and collateral read from file.
        let get_msg = QueryMsg::GetSecretKey { service_id: "0".to_string(), quote, collateral, password: None};
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
        let create_msg = ExecuteMsg::CreateService { name: "UnauthorizedTest".to_string(), service_id: "0".to_string(), password_hash: None};
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
        let add_msg = ExecuteMsg::AddImageToService { service_id: "0".to_string(), description: "TestImage".to_string(), image_filter, timestamp: None };
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
            ExecuteMsg::CreateService { service_id: svc_id.clone(), name: "Svc".to_string(), password_hash: None},
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
                timestamp: None,
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
            vm_uid: Some(vm_uid),
        };

        // Store the secret key for this image
        execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            ExecuteMsg::AddSecretKeyByImage { image_filter: image_filter.clone(), password_hash: None},
        ).unwrap();

        // Now query by image
        let query_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyByImage { quote: quote.clone(), collateral: collateral.clone(), password: None}
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
            password_hash: None
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
        let res = try_get_secret_key_by_image(deps.as_ref(), mock_env(), quote, collateral, None);
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
                password_hash: None
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
            QueryMsg::GetEnvByImage { quote, collateral, password: None}
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
                password_hash: None
            },
        )
            .expect("AddEnvByImage must succeed");

        // --- Step 5. Query GetEnvByImage and verify ---
        let res_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage { quote: quote.clone(), collateral: collateral.clone(), password: None},
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
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string(), password_hash: None}
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
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string(), password_hash: None}
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
                timestamp: None,
            }
        ).unwrap();

        // Build dummy quote
        let quote_len = std::mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len]; quote[0]=4; quote[4]=129;
        let collateral = vec![0u8;10];
        let err = try_get_env_by_service(
            deps.as_ref(), mock_env(), "svc1".to_string(), quote, collateral, None
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
            ExecuteMsg::CreateService { service_id: "svc1".to_string(), name: "Test".to_string(), password_hash: None}
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
                timestamp: None,
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
            QueryMsg::GetEnvByService { service_id: "svc1".to_string(), quote, collateral, password: None}
        ).unwrap();
        let resp: EnvSecretResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secrets_plaintext.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }
    #[test]
    fn add_image_with_explicit_timestamp_is_stored() {
        use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService { service_id: "svc".into(), name: "N".into(), password_hash: None}
        ).unwrap();

        let image_filter = MsgImageFilter {
            mr_seam: None, mr_signer_seam: None, mr_td: Some(vec![1;48]),
            mr_config_id: None, mr_owner: None, mr_config: None,
            rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None, vm_uid: None,
        };

        let explicit_ts = 1_725_000_000u64;
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc".into(),
                image_filter: image_filter.clone(),
                description: "d".into(),
                timestamp: Some(explicit_ts),   // <-- explicit
            }
        ).unwrap();

        // Read back from storage and assert timestamp
        let svc = SERVICES_MAP.get(&deps.storage, &"svc".to_string()).unwrap();
        assert_eq!(svc.filters.len(), 1);
        assert_eq!(svc.filters[0].timestamp, Some(explicit_ts));
    }
    #[test]
    fn add_image_without_timestamp_uses_block_time() {
        use cosmwasm_std::{testing::{mock_dependencies, mock_info}, Timestamp};
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService { service_id: "svc".into(), name: "N".into(), password_hash: None}
        ).unwrap();

        let image_filter = MsgImageFilter {
            mr_seam: None, mr_signer_seam: None, mr_td: Some(vec![2;48]),
            mr_config_id: None, mr_owner: None, mr_config: None,
            rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None, vm_uid: None,
        };

        // Prepare env with a known timestamp
        let mut env = mock_env();
        env.block.time = Timestamp::from_seconds(42);

        execute(
            deps.as_mut(),
            env.clone(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc".into(),
                image_filter: image_filter.clone(),
                description: "d2".into(),
                timestamp: None,               // <-- omitted -> use env.block.time
            }
        ).unwrap();

        let svc = SERVICES_MAP.get(&deps.storage, &"svc".to_string()).unwrap();
        assert_eq!(svc.filters.len(), 1);
        assert_eq!(svc.filters[0].timestamp, Some(42));
    }

    #[test]
    fn migrate_moves_services_v1_to_v2() {
        use cosmwasm_std::testing::{mock_dependencies, mock_env};
        use cosmwasm_std::Addr;
        use crate::state::*;
        use crate::contract::migrate;
        use crate::msg::MigrateMsg;

        let mut deps = mock_dependencies();

        // Seed OLD_SERVICES_MAP with one legacy service (no timestamps in filters, no password_hash)
        let key = "svc-old-1".to_string();
        let old = OldService {
            id: "svc-old-1".into(),
            name: "Legacy".into(),
            admin: Addr::unchecked("admin"),
            filters: vec![
                FilterEntry {
                    filter: ImageFilter {
                        mr_seam: None, mr_signer_seam: None, mr_td: Some(vec![1; 48]),
                        mr_config_id: None, mr_owner: None, mr_config: None,
                        rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None,
                    },
                    description: "legacy-filter".into(),
                    timestamp: None
                }
            ],
            secret_key: vec![9; 32],
            secrets_plaintext: Some("legacy-secret".into()),
        };
        OLD_SERVICES_MAP.insert(deps.as_mut().storage, &key, &old).unwrap();

        // Run migrate
        let resp = migrate(deps.as_mut(), mock_env(), MigrateMsg::Migrate {}).unwrap();

        // Basic action attribute exists (exact value may differ between versions)
        assert!(
            resp.attributes.iter().any(|a| a.key == "action"),
            "migration response must contain 'action' attribute"
        );

        // Old removed
        assert!(
            OLD_SERVICES_MAP.get(&deps.storage, &key).is_none(),
            "old map entry should be removed after migration"
        );

        // New exists with timestamp == None on filters, payload preserved
        let new = SERVICES_MAP
            .get(&deps.storage, &key)
            .expect("new service must exist");

        assert_eq!(new.id, "svc-old-1");
        assert_eq!(new.name, "Legacy");
        assert_eq!(new.admin, Addr::unchecked("admin"));

        // filters migrated; legacy filter has timestamp == None
        assert_eq!(new.filters.len(), 1);
        assert_eq!(new.filters[0].description, "legacy-filter");
        assert_eq!(new.filters[0].timestamp, None);

        // payload migrated as-is
        assert_eq!(new.secret_key, vec![9; 32]);
        assert_eq!(new.secrets_plaintext.as_deref(), Some("legacy-secret"));

        // password_hash must be None for migrated legacy entries
        // (the new Service struct should have an Option<String> password_hash with #[serde(default)])
        assert_eq!(new.password_hash, None);
    }

    // ---- helpers for passworded tests ----
    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        hex::encode(h.finalize())
    }

    /// Build a minimal, structurally-valid TDX quote:
    /// - header.version=4, header.tee_type=0x81
    /// - report_data[0..32] = dummy pubkey (all ones)
    /// - report_data[32..48] = provided vm_uid (16 bytes)
    fn build_dummy_quote_with_vm_uid(vm_uid: &[u8; 16]) -> Vec<u8> {
        let quote_len = std::mem::size_of::<tdx_quote_t>();
        let mut quote = vec![0u8; quote_len];

        // version = 4 (u16 LE)
        quote[0] = 4; quote[1] = 0;
        // tee_type = 0x81 (u32 LE)
        quote[4] = 129; quote[5] = 0; quote[6] = 0; quote[7] = 0;

        // report_data tail (64 bytes at end of quote)
        let rd_off = quote_len - 64;
        // 32-byte "other" pubkey, all ones
        for i in rd_off..(rd_off + 32) { quote[i] = 1; }
        // put vm_uid (16 bytes) right after pubkey
        quote[rd_off + 32..rd_off + 48].copy_from_slice(vm_uid);
        quote
    }

    #[test]
    fn service_password_enforced_for_get_secret_key() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        // Create service with password protection
        let pwd_plain = "p@ss-123";
        let pwd_hash = sha256_hex(pwd_plain);
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService {
                service_id: "svc_pwd".into(),
                name: "Protected".into(),
                password_hash: Some(pwd_hash),
            }
        ).unwrap();

        // Add a permissive filter (all None => matches any valid quote)
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc_pwd".into(),
                image_filter: MsgImageFilter {
                    mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None,
                    mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None,
                    vm_uid: None,
                },
                description: "any".into(),
                timestamp: None,
            }
        ).unwrap();

        // Build a minimal valid quote/collateral
        let mut quote = vec![0u8; std::mem::size_of::<tdx_quote_t>()];
        quote[0] = 4; quote[1] = 0;      // version
        quote[4] = 129; quote[5] = 0;    // tee_type
        let collateral = vec![0u8; 4];

        // 1) No password -> "Password required"
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKey {
                service_id: "svc_pwd".into(),
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: None,
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password required");

        // 2) Wrong password -> "Password mismatch"
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKey {
                service_id: "svc_pwd".into(),
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: Some("wrong".into()),
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password mismatch");

        // 3) Correct password -> success
        let bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKey {
                service_id: "svc_pwd".into(),
                quote,
                collateral,
                password: Some(pwd_plain.into()),
            }
        ).unwrap();
        let resp: SecretKeyResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secret_key.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn service_password_enforced_for_get_env() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        // Passworded service + env
        let pwd_plain = "env-pass";
        let pwd_hash = sha256_hex(pwd_plain);
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateService {
                service_id: "svc_env_pwd".into(),
                name: "ProtectedENV".into(),
                password_hash: Some(pwd_hash),
            }
        ).unwrap();

        // Add permissive filter
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddImageToService {
                service_id: "svc_env_pwd".into(),
                image_filter: MsgImageFilter {
                    mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None,
                    mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None,
                    vm_uid: None,
                },
                description: "".into(),
                timestamp: None,
            }
        ).unwrap();

        // Store env secret at service level
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddEnvByService {
                service_id: "svc_env_pwd".into(),
                secrets_plaintext: "ENV=1".into(),
            }
        ).unwrap();

        // Dummy quote
        let mut quote = vec![0u8; std::mem::size_of::<tdx_quote_t>()];
        quote[0] = 4; quote[1] = 0;      // version
        quote[4] = 129; quote[5] = 0;    // tee_type
        let collateral = vec![0u8; 4];

        // No password -> required
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByService {
                service_id: "svc_env_pwd".into(),
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: None,
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password required");

        // Wrong -> mismatch
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByService {
                service_id: "svc_env_pwd".into(),
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: Some("nope".into()),
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password mismatch");

        // Correct -> success
        let bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByService {
                service_id: "svc_env_pwd".into(),
                quote,
                collateral,
                password: Some(pwd_plain.into()),
            }
        ).unwrap();
        let resp: EnvSecretResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secrets_plaintext.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn vm_password_enforced_for_get_secret_key_by_image() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        // Prepare VM UID and quote/collateral
        let vm_uid: [u8; 16] = *b"0123456789abcdef";
        let quote = build_dummy_quote_with_vm_uid(&vm_uid);
        let collateral = vec![0u8; 8];

        // Add VM secret with password_hash through ExecuteMsg::AddSecretKeyByImage
        let pwd_plain = "vm-pass";
        let pwd_hash = sha256_hex(pwd_plain);
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddSecretKeyByImage {
                image_filter: MsgImageFilter {
                    // Store permissive filter; it will match the quote
                    mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None,
                    mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None,
                    vm_uid: Some(vm_uid.to_vec()),
                },
                password_hash: Some(pwd_hash),
            }
        ).unwrap();

        // 1) No password -> required
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyByImage {
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: None,
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password required");

        // 2) Wrong -> mismatch
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyByImage {
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: Some("bad".into()),
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password mismatch");

        // 3) Correct -> success
        let bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyByImage {
                quote,
                collateral,
                password: Some(pwd_plain.into()),
            }
        ).unwrap();
        let resp: SecretKeyResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secret_key.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn vm_password_enforced_for_get_env_by_image() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        let vm_uid: [u8; 16] = *b"ABCDEF0123456789";
        let quote = build_dummy_quote_with_vm_uid(&vm_uid);
        let collateral = vec![0u8; 8];

        // Add VM env with password_hash through ExecuteMsg::AddEnvByImage
        let pwd_plain = "env-vm-pass";
        let pwd_hash = sha256_hex(pwd_plain);
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddEnvByImage {
                image_filter: MsgImageFilter {
                    mr_seam: None, mr_signer_seam: None, mr_td: None, mr_config_id: None,
                    mr_owner: None, mr_config: None, rtmr0: None, rtmr1: None, rtmr2: None, rtmr3: None,
                    vm_uid: Some(vm_uid.to_vec()),
                },
                secrets_plaintext: "ENV=VM".into(),
                password_hash: Some(pwd_hash),
            }
        ).unwrap();

        // 1) No password -> required
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage {
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: None,
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password required");

        // 2) Wrong -> mismatch
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage {
                quote: quote.clone(),
                collateral: collateral.clone(),
                password: Some("no".into()),
            }
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password mismatch");

        // 3) Correct -> success
        let bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImage {
                quote,
                collateral,
                password: Some(pwd_plain.into()),
            }
        ).unwrap();
        let resp: EnvSecretResponse = from_binary(&bin).unwrap();
        assert!(!resp.encrypted_secrets_plaintext.is_empty());
        assert!(!resp.encryption_pub_key.is_empty());
    }

    // =========================================================================
    // AMD TESTS
    // =========================================================================

    // A valid AMD SEV-SNP Report (Base64) matching the hardcoded certificates in amd_attest.rs
    // Measurement: 45fcf00a5bc0888f451cddaecba9a9f783543e72b319e14df388c82a3dcebbd348b0b0c5aef22c5432e65c8997fe6fc6
    const VALID_AMD_REPORT_B64: &str = "AwAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAJAAAAAAAXSCcAAAAAAAAAAAAAAAAAAAACeDeESh3+s2BOgyl00cecxRfl4tTUlYiJZD4XcWD+NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARfzwClvAiI9FHN2uy6mp94NUPnKzGeFN84jIKj3Ou9NIsLDFrvIsVDLmXImX/m/GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiVRLNzxQCo/Ld3rkBXFn9U7kSgO4TOP8AKnqTleNnk///////////////////////////////////////////CQAAAAAAF0gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAACvcHTqpO6FT+BKGvSEX2JkXa2Yg/MNRbPYqkfltgmTo2gMTrCo6UXD9lMkAJtxE/W37TYGJ/PL+WliY7NYWmKjCQAAAAAAF0gnNwEAJzcBAAkAAAAAABdIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmvkwlMgGTaEGGO7x1whLf5hbvXDwNp514Rnc/70W779+Yi5iPS3cR0K5n3EmA+siAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATV33Rm6swqfKHv4N9neM7/9lWog7vxhygd0awl1XQrSP0IT9PqMJ6rD1dphA5ff8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    const EXPECTED_AMD_MEASUREMENT_HEX: &str = "45fcf00a5bc0888f451cddaecba9a9f783543e72b319e14df388c82a3dcebbd348b0b0c5aef22c5432e65c8997fe6fc6";

    #[test]
    fn amd_create_service_and_list() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // 1. Create AMD Service
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::CreateAmdService {
                service_id: "amd-svc-1".to_string(),
                name: "AMD Service".to_string(),
                password_hash: None,
            },
        ).unwrap();

        // 2. Add Filter
        let measurement = hex::decode(EXPECTED_AMD_MEASUREMENT_HEX).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddAmdImageToService {
                service_id: "amd-svc-1".to_string(),
                image_filter: AmdMsgImageFilter {
                    measurement: Some(measurement.clone()),
                    vm_uid: None,
                },
                description: "Initial AMD Filter".to_string(),
                timestamp: None,
            },
        ).unwrap();

        // 3. List Services (Verify isolation from TDX maps)
        let tdx_list = query_services(deps.as_ref()).unwrap();
        assert_eq!(tdx_list.len(), 0, "AMD service should not appear in TDX list");

        let amd_list = query_amd_services(deps.as_ref()).unwrap();
        assert_eq!(amd_list.len(), 1);
        assert_eq!(amd_list[0].id, "amd-svc-1");

        // 4. List Filters
        let filters = query_amd_image_filters(deps.as_ref(), "amd-svc-1".to_string()).unwrap();
        assert_eq!(filters.filters.len(), 1);
        assert_eq!(filters.filters[0].description, "Initial AMD Filter");
        assert_eq!(filters.filters[0].measurement, Some(EXPECTED_AMD_MEASUREMENT_HEX.to_string()));
    }

    #[test]
    fn amd_get_secret_key_service_flow() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        // 1. Setup Service
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateAmdService {
                service_id: "amd-svc-key".to_string(),
                name: "Key Service".to_string(),
                password_hash: None,
            },
        ).unwrap();

        // 2. Add matching filter (Measurement from VALID_AMD_REPORT_B64)
        let measurement = hex::decode(EXPECTED_AMD_MEASUREMENT_HEX).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddAmdImageToService {
                service_id: "amd-svc-key".to_string(),
                image_filter: AmdMsgImageFilter {
                    measurement: Some(measurement),
                    vm_uid: None,
                },
                description: "Valid Filter".to_string(),
                timestamp: None,
            },
        ).unwrap();

        // 3. Get Secret Key
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyAmd {
                service_id: "amd-svc-key".to_string(),
                report: VALID_AMD_REPORT_B64.to_string(),
                password: None,
            },
        ).unwrap();

        let key_resp: SecretKeyResponse = from_binary(&res).unwrap();
        assert!(!key_resp.encrypted_secret_key.is_empty());
        assert!(!key_resp.encryption_pub_key.is_empty());
    }

    #[test]
    fn amd_get_env_by_image_flow() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();
        let vm_uid = vec![0u8; 16];
        let measurement = hex::decode(EXPECTED_AMD_MEASUREMENT_HEX).unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddAmdEnvByImage {
                image_filter: AmdMsgImageFilter {
                    measurement: Some(measurement.clone()),
                    vm_uid: Some(vm_uid.clone()),
                },
                secrets_plaintext: "AMD_ENV_VAR=SUCCESS".to_string(),
                password_hash: None,
            },
        ).unwrap();

        // Query
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByImageAmd {
                report: VALID_AMD_REPORT_B64.to_string(),
                password: None,
            },
        ).unwrap();

        let env_resp: EnvSecretResponse = from_binary(&res).unwrap();
        assert!(!env_resp.encrypted_secrets_plaintext.is_empty());
    }

    #[test]
    fn amd_password_protection() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        let pwd_plain = "secret-amd";
        let pwd_hash = sha256_hex(pwd_plain);

        // Create service with password
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateAmdService {
                service_id: "amd-pwd".to_string(),
                name: "Secure AMD".to_string(),
                password_hash: Some(pwd_hash),
            },
        ).unwrap();

        let measurement = hex::decode(EXPECTED_AMD_MEASUREMENT_HEX).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddAmdImageToService {
                service_id: "amd-pwd".to_string(),
                image_filter: AmdMsgImageFilter {
                    measurement: Some(measurement),
                    vm_uid: None,
                },
                description: "desc".to_string(),
                timestamp: None,
            },
        ).unwrap();

        // 1. Fail without password
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyAmd {
                service_id: "amd-pwd".to_string(),
                report: VALID_AMD_REPORT_B64.to_string(),
                password: None,
            },
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password required");

        // 2. Fail with wrong password
        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyAmd {
                service_id: "amd-pwd".to_string(),
                report: VALID_AMD_REPORT_B64.to_string(),
                password: Some("wrong".to_string()),
            },
        ).unwrap_err();
        assert_eq!(err.to_string(), "Generic error: Password mismatch");

        // 3. Success
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetSecretKeyAmd {
                service_id: "amd-pwd".to_string(),
                report: VALID_AMD_REPORT_B64.to_string(),
                password: Some(pwd_plain.to_string()),
            },
        ).unwrap();
        let resp: SecretKeyResponse = from_binary(&res).unwrap();
        assert!(!resp.encrypted_secret_key.is_empty());
    }

    #[test]
    fn amd_get_env_by_service() {
        let mut deps = mock_dependencies();
        let admin = mock_info("admin", &[]);
        instantiate(deps.as_mut(), mock_env(), admin.clone(), InstantiateMsg {}).unwrap();

        let service_id = "amd-svc-env".to_string();

        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::CreateAmdService {
                service_id: service_id.clone(),
                name: "Env Service".to_string(),
                password_hash: None,
            },
        ).unwrap();

        // Add filter so the report matches
        let measurement = hex::decode(EXPECTED_AMD_MEASUREMENT_HEX).unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddAmdImageToService {
                service_id: service_id.clone(),
                image_filter: AmdMsgImageFilter {
                    measurement: Some(measurement),
                    vm_uid: None,
                },
                description: "filter".to_string(),
                timestamp: None,
            },
        ).unwrap();

        // Add Service Env
        execute(
            deps.as_mut(),
            mock_env(),
            admin.clone(),
            ExecuteMsg::AddAmdEnvByService {
                service_id: service_id.clone(),
                secrets_plaintext: "SERVICE_SECRET=123".to_string(),
            },
        ).unwrap();

        // Query
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetEnvByServiceAmd {
                service_id: service_id,
                report: VALID_AMD_REPORT_B64.to_string(),
                password: None,
            },
        ).unwrap();

        let resp: EnvSecretResponse = from_binary(&res).unwrap();
        assert!(!resp.encrypted_secrets_plaintext.is_empty());
    }
}
