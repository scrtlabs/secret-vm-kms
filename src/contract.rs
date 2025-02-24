use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, Event, attr, attr_plaintext};
use sha2::{Digest, Sha256};
use hex;
use core::mem;
#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use sha2::digest::Update;
use thiserror::Error;
use crate::crypto::{KeyPair, SIVEncryptable, SECRET_KEY_SIZE};
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, MsgImageFilter, QueryMsg, SecretKeyResponse, ServiceResponse};
use crate::state::{global_state, global_state_read, services, services_read, GlobalState, Service, ImageFilter};
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
fn dcap_quote_verify_internal(quote: &[u8], collateral: &[u8]) -> Result<u32, SigningErrorC> {
    // Pack the input data into memory regions for FFI
    let quote_region = build_region(quote);
    let quote_ptr = &*quote_region as *const Region as u32;

    let collateral_region = build_region(collateral);
    let collateral_ptr = &*collateral_region as *const Region as u32;

    // Call the external function to verify the DCAP quote
    let result = unsafe { dcap_quote_verify(quote_ptr, collateral_ptr) };

    // Decode the returned 64-bit value:
    // - The high half is the error code.
    // - The low half is the verification result.
    let error_code = from_high_half(result);
    let verify_result = from_low_half(result);

    // Process the result based on the error code
    match error_code {
        0 => Ok(verify_result),
        error_code => Err(SigningErrorC::UnknownErr {
            error_code,
        }),
    }
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
            // // Iterate through all API keys and remove them
            // let keys_to_remove: Vec<String> = API_KEY_MAP
            //     .iter_keys(deps.storage)?
            //     .filter_map(|key_result| key_result.ok())
            //     .collect();
            //
            // for key in keys_to_remove {
            //     API_KEY_MAP.remove(deps.storage, &key)?;
            // }

            Ok(Response::new()
                .add_attribute("action", "migrate"))
        }
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

/// Instantiate the contract. Initializes global state and an empty services list.
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    let gs = GlobalState { service_count: 0 };
    global_state(deps.storage).save(&gs)?;
    let svc_list: Vec<Service> = Vec::new();
    services(deps.storage).save(&svc_list)?;
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
    }
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
    let shared_key = kp.diffie_hellman(&kp.get_pubkey());
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

/// Query entry point for handling QueryMsg.
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetService { id } => to_binary(&query_service(deps, id)?),
        QueryMsg::ListServices {} => to_binary(&query_services(deps)?),
        QueryMsg::GetSecretKey { service_id, quote, collateral } => to_binary(&try_get_secret_key(deps,env, service_id, quote, collateral)?),
    }
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
